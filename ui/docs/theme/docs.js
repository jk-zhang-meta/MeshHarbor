/* SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2026 G ROX EOOD
 *
 * FR-60 (#1165) — page behaviour: OS-tab persistence, copy buttons, the
 * mobile nav, and TOC scroll-spy. Every static page loads it (docs, blog and
 * the homepage), so it also fires two of FR-88's purestat goals:
 * `install-copy` from an install/enroll command's copy button, and
 * `github-outbound` from a link to the repository.
 *
 * Every one of these is a PROGRESSIVE ENHANCEMENT. With JavaScript off:
 * the OS tabs still switch (CSS `:checked`), code is still selectable, the
 * sidebar is still reachable (it renders in the flow below 900px once the
 * burger is gone), and the TOC is still a list of working anchors. Nothing
 * here is load-bearing for reading the documentation.
 */
;(function () {
  'use strict'

  var OS_KEY = 'meshharbor-docs-os'
  var VALID_OS = { windows: 1, macos: 1, linux: 1 }

  function readOs() {
    try {
      var v = localStorage.getItem(OS_KEY)
      return VALID_OS[v] ? v : null
    } catch (e) {
      return null
    }
  }

  function writeOs(os) {
    try {
      localStorage.setItem(OS_KEY, os)
    } catch (e) {
      /* private window / site data blocked — the choice just does not persist */
    }
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

  // ── OS tabs ───────────────────────────────────────────────────────────
  function syncOs(os, groups) {
    for (var i = 0; i < groups.length; i++) {
      var radio = groups[i].querySelector('.os-radio--' + os)
      // A group that does not offer this OS keeps whatever it had — a
      // Linux-only block must not blank out because the reader is on macOS.
      if (radio && !radio.checked) radio.checked = true
    }
  }

  function initOsTabs() {
    var groups = document.querySelectorAll('[data-os-tabs]')
    if (!groups.length) {
      document.documentElement.removeAttribute('data-os')
      return
    }

    var stored = readOs()
    if (stored) syncOs(stored, groups)
    // Hand control back to the CSS-only mechanism now that the real radios
    // hold the state. Leaving the attribute would pin every group to one OS
    // and defeat the per-group fallback above.
    document.documentElement.removeAttribute('data-os')

    document.addEventListener('change', function (ev) {
      var t = ev.target
      if (!t || !t.classList || !t.classList.contains('os-radio')) return
      var os = null
      for (var key in VALID_OS) {
        if (t.classList.contains('os-radio--' + key)) os = key
      }
      if (!os) return
      writeOs(os)
      syncOs(os, groups)
    })
  }

  // ── copy buttons ──────────────────────────────────────────────────────
  function initCopy() {
    document.addEventListener('click', function (ev) {
      var btn = ev.target && ev.target.closest ? ev.target.closest('.code-copy') : null
      if (!btn) return
      var block = btn.closest('[data-code]')
      var code = block && block.querySelector('code')
      if (!code) return

      var done = function () {
        // `data-install`: the build recognised an agent install or enroll
        // command (`isInstallCommand` in render.ts).
        if (block.hasAttribute('data-install')) goal('install-copy')
        btn.classList.add('is-copied')
        btn.setAttribute('aria-label', 'Copied')
        setTimeout(function () {
          btn.classList.remove('is-copied')
          btn.setAttribute('aria-label', 'Copy code to clipboard')
        }, 1400)
      }

      // navigator.clipboard is undefined outside a secure context, and the
      // docs are readable over plain http on a self-hosted LAN instance —
      // so the legacy path is a real fallback here, not belt-and-braces.
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(code.textContent).then(done, function () {})
        return
      }
      var ta = document.createElement('textarea')
      ta.value = code.textContent
      ta.setAttribute('readonly', '')
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      try {
        document.execCommand('copy')
        done()
      } catch (e) {
        /* nothing sensible to do; the text is still selectable by hand */
      }
      document.body.removeChild(ta)
    })
  }

  // ── the repository goal (FR-88) ───────────────────────────────────────
  // Any link into the repository: the top bar's GitHub link, the ones in the
  // prose, "Edit this page". Not the author's profile, not another repo.
  var REPO = /^https:\/\/github\.com\/gjovanov\/meshharbor(?:[/?#]|\.git|$)/i

  function initOutbound() {
    function onClick(ev) {
      var a = ev.target && ev.target.closest ? ev.target.closest('a[href]') : null
      if (a && REPO.test(a.href)) goal('github-outbound')
    }
    document.addEventListener('click', onClick)
    // A middle click opens the link in a new tab without any `click` event.
    document.addEventListener('auxclick', function (ev) {
      if (ev.button === 1) onClick(ev)
    })
  }

  // ── mobile nav ────────────────────────────────────────────────────────
  function initNav() {
    var toggle = document.querySelector('[data-nav-toggle]')
    var nav = document.querySelector('[data-nav]')
    if (!toggle || !nav) return
    toggle.addEventListener('click', function () {
      var open = nav.classList.toggle('is-open')
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false')
    })
  }

  // ── TOC scroll-spy ────────────────────────────────────────────────────
  function initScrollSpy() {
    var links = document.querySelectorAll('.toc__item a')
    if (!links.length || !('IntersectionObserver' in window)) return

    var byId = {}
    var targets = []
    for (var i = 0; i < links.length; i++) {
      var id = decodeURIComponent(links[i].getAttribute('href').slice(1))
      var el = document.getElementById(id)
      if (!el) continue
      byId[id] = links[i]
      targets.push(el)
    }
    if (!targets.length) return

    var visible = {}
    var obs = new IntersectionObserver(
      function (entries) {
        for (var i = 0; i < entries.length; i++) {
          visible[entries[i].target.id] = entries[i].isIntersecting
        }
        // The first heading currently in the band wins, so the highlight
        // reads top-down like the page does rather than jumping to
        // whichever entry the observer happened to report last.
        var currentId = null
        for (var j = 0; j < targets.length; j++) {
          if (visible[targets[j].id]) {
            currentId = targets[j].id
            break
          }
        }
        for (var id in byId) byId[id].classList.remove('is-current')
        if (currentId && byId[currentId]) byId[currentId].classList.add('is-current')
      },
      { rootMargin: '-76px 0px -68% 0px', threshold: 0 },
    )
    for (var k = 0; k < targets.length; k++) obs.observe(targets[k])
  }

  // FR-88 (#1790) P3 — the video facade (`theme/video.ts`): a click swaps the
  // poster link for the youtube-nocookie player, so nothing loads from YouTube
  // before someone asks for it. Without JavaScript, the link opens the video
  // on YouTube; a modified or middle click keeps that behaviour too.
  function initVideos() {
    document.addEventListener('click', function (e) {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
      var a = e.target && e.target.closest ? e.target.closest('a[data-video-id]') : null
      if (!a) return
      var id = a.getAttribute('data-video-id') || ''
      if (!/^[A-Za-z0-9_-]{11}$/.test(id)) return
      e.preventDefault()
      var f = document.createElement('iframe')
      f.className = 'video-facade__player'
      f.src = 'https://www.youtube-nocookie.com/embed/' + id + '?autoplay=1&rel=0'
      f.title = a.getAttribute('data-video-title') || 'Video'
      f.setAttribute('allow', 'autoplay; encrypted-media; picture-in-picture; fullscreen')
      f.setAttribute('allowfullscreen', '')
      a.parentNode.replaceChild(f, a)
      f.focus()
    })
  }

  function boot() {
    initOsTabs()
    initCopy()
    initOutbound()
    initNav()
    initScrollSpy()
    initVideos()
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot)
  } else {
    boot()
  }
})()
