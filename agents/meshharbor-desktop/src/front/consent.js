// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
// Phase 3 — remote-control consent popup.
//
// Polls the tray backend for `.pending` markers the agent drops when a remote
// session is awaiting a decision, renders an Approve/Deny modal, and writes the
// operator's choice through the existing cmd_consent_approve / cmd_consent_deny
// commands. Self-contained: it creates its own modal DOM (no dependency on the
// app shell) and overlays whichever view is active.
//
// The Rust-side watcher brings the window forward when a new marker appears;
// this loop does the rendering and the decision.
(function () {
  const invoke = (name, payload) => window.__TAURI__.core.invoke(name, payload || {})
  const t = (key, params, fallback) =>
    window.MeshHarborI18n ? window.MeshHarborI18n.t(key, params) : fallback

  let activeSession = null // session id currently shown in the modal
  let currentPrompt = null
  let busy = false // an approve/deny call is in flight

  function ensureModal() {
    let el = document.getElementById('consent-modal')
    if (el) return el
    el = document.createElement('div')
    el.id = 'consent-modal'
    el.hidden = true
    el.innerHTML = [
      '<div class="consent-backdrop"></div>',
      '<div class="consent-card" role="dialog" aria-modal="true" aria-labelledby="consent-title">',
      '  <h2 id="consent-title" data-i18n="consent.rc.title">Remote control request</h2>',
      '  <p class="consent-lead"><strong id="consent-who"></strong> <span id="consent-verb">is requesting to control this device</span>.</p>',
      // Multi-org: on a device enrolled in more than one organization, WHO is
      // asking is only half the question — the same person can be a colleague
      // in one org and an outside contractor in another. Hidden entirely when
      // the daemon sends no org (single-org device, or an older daemon).
      '  <p class="consent-org" id="consent-org-row" hidden><span data-i18n="consent.orgPrefix">On behalf of </span><strong id="consent-org"></strong></p>',
      // FR-27 — WHAT is being asked for, when that is not implied by the
      // request type: the command an `exec` would run, the activity an SSH
      // session wants. Rendered with textContent (never innerHTML): this
      // string originates off-device and is redacted, not sanitised.
      '  <p class="consent-detail" id="consent-detail-row" hidden><span id="consent-detail" class="mono"></span></p>',
      '  <p class="consent-perms" id="consent-perms-row"><span data-i18n="consent.permsPrefix">Permissions: </span><span id="consent-perms" class="mono"></span></p>',
      '  <div class="consent-actions">',
      '    <button type="button" id="consent-deny" class="consent-btn consent-deny" data-i18n="consent.deny">Deny</button>',
      '    <button type="button" id="consent-approve" class="consent-btn consent-approve" data-i18n="consent.approve">Approve</button>',
      '  </div>',
      '  <p class="consent-hint muted small" id="consent-hint"></p>',
      '</div>',
    ].join('\n')
    document.body.appendChild(el)
    if (window.MeshHarborI18n) window.MeshHarborI18n.applyI18n(el)
    el.querySelector('#consent-approve').addEventListener('click', () => decide(true))
    el.querySelector('#consent-deny').addEventListener('click', () => decide(false))
    return el
  }

  async function decide(approve) {
    if (!activeSession || busy) return
    busy = true
    const hint = document.getElementById('consent-hint')
    if (hint) {
      hint.textContent = approve
        ? t('consent.approving', null, 'Approving…')
        : t('consent.denying', null, 'Denying…')
    }
    try {
      await invoke(approve ? 'cmd_consent_approve' : 'cmd_consent_deny', { session: activeSession })
      hide()
    } catch (e) {
      if (hint) hint.textContent = t('common.failedPrefix', { err: e }, 'Failed: ' + e)
    } finally {
      busy = false
    }
  }

  // FR-27 - the modal now serves THREE subsystems, and they are not the same
  // question. An `exec` prompt rendered as "wants to control this device"
  // would be a plain lie about a command that runs as SYSTEM/root, so the
  // title and the verb are driven by `kind`.
  //
  // An ABSENT kind means a pre-FR-27 daemon, which only ever wrote remote
  // control prompts - so the fallback is `rc`, not "unknown".
  const KIND_KEYS = {
    rc: {
      titleKey: 'consent.rc.title',
      titleFallback: 'Remote control request',
      verbKey: 'consent.rc.verb',
      verbFallback: 'is requesting to control this device',
    },
    exec: {
      titleKey: 'consent.exec.title',
      titleFallback: 'Command execution request',
      verbKey: 'consent.exec.verb',
      verbFallback: 'wants to run a command on this device',
    },
    ssh: {
      titleKey: 'consent.ssh.title',
      titleFallback: 'SSH session request',
      verbKey: 'consent.ssh.verb',
      verbFallback: 'wants to open an SSH session on this device',
    },
    record: {
      titleKey: 'consent.record.title',
      titleFallback: 'Screen recording request',
      verbKey: 'consent.record.verb',
      verbFallback: 'wants to record this screen',
    },
  }

  function show(pc) {
    const el = ensureModal()
    activeSession = pc.session_id
    currentPrompt = pc
    const kind = KIND_KEYS[pc.kind] || KIND_KEYS.rc
    document.getElementById('consent-title').textContent = t(kind.titleKey, null, kind.titleFallback)
    document.getElementById('consent-verb').textContent = t(kind.verbKey, null, kind.verbFallback)
    document.getElementById('consent-who').textContent =
      pc.controller_name || t('consent.whoFallback', null, 'A remote operator')
    const orgRow = document.getElementById('consent-org-row')
    if (orgRow) {
      const org = (pc.org || '').trim()
      document.getElementById('consent-org').textContent = org
      orgRow.hidden = org === ''
    }
    const detailRow = document.getElementById('consent-detail-row')
    if (detailRow) {
      const detail = (pc.detail || '').trim()
      document.getElementById('consent-detail').textContent = detail
      detailRow.hidden = detail === ''
    }
    // Only remote control carries a permission set; showing "Permissions: -"
    // above an exec prompt reads as "no permissions needed", which is the
    // opposite of true for a command running as the daemon identity.
    const permsRow = document.getElementById('consent-perms-row')
    if (permsRow) permsRow.hidden = !pc.permissions
    document.getElementById('consent-perms').textContent = pc.permissions || '—'
    document.getElementById('consent-hint').textContent = ''
    el.hidden = false
  }

  function hide() {
    const el = document.getElementById('consent-modal')
    if (el) el.hidden = true
    activeSession = null
    currentPrompt = null
  }

  async function poll() {
    let pending
    try {
      pending = await invoke('cmd_get_pending_consents')
    } catch (_) {
      return // backend not ready / dir absent — stay quiet
    }
    // FR-27 — skip anything the daemon already shows natively; see
    // panel-consent.js. Two Approve buttons for one decision is how someone
    // approves the wrong thing.
    if (Array.isArray(pending)) pending = pending.filter((p) => p.surface !== 'native')
    if (Array.isArray(pending) && pending.length > 0) {
      // Keep showing the current one if it's still pending; otherwise show the
      // first outstanding request (an operator may have resolved one elsewhere).
      if (!activeSession || !pending.some((p) => p.session_id === activeSession)) {
        show(pending[0])
      }
    } else if (activeSession && !busy) {
      hide() // resolved (e.g. via CLI, or timed out) — dismiss the modal
    }
  }

  document.addEventListener('meshharbor:lang', () => {
    if (currentPrompt) show(currentPrompt)
  })

  setInterval(poll, 1500)
  poll()
})()
