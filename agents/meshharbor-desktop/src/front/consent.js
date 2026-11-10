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

  let activeSession = null // session id currently shown in the modal
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
      '  <h2 id="consent-title">Remote control request</h2>',
      '  <p class="consent-lead"><strong id="consent-who"></strong> <span id="consent-verb">is requesting to control this device</span>.</p>',
      // Multi-org: on a device enrolled in more than one organization, WHO is
      // asking is only half the question — the same person can be a colleague
      // in one org and an outside contractor in another. Hidden entirely when
      // the daemon sends no org (single-org device, or an older daemon).
      '  <p class="consent-org" id="consent-org-row" hidden>On behalf of <strong id="consent-org"></strong></p>',
      // FR-27 — WHAT is being asked for, when that is not implied by the
      // request type: the command an `exec` would run, the activity an SSH
      // session wants. Rendered with textContent (never innerHTML): this
      // string originates off-device and is redacted, not sanitised.
      '  <p class="consent-detail" id="consent-detail-row" hidden><span id="consent-detail" class="mono"></span></p>',
      '  <p class="consent-perms" id="consent-perms-row">Permissions: <span id="consent-perms" class="mono"></span></p>',
      '  <div class="consent-actions">',
      '    <button type="button" id="consent-deny" class="consent-btn consent-deny">Deny</button>',
      '    <button type="button" id="consent-approve" class="consent-btn consent-approve">Approve</button>',
      '  </div>',
      '  <p class="consent-hint muted small" id="consent-hint"></p>',
      '</div>',
    ].join('\n')
    document.body.appendChild(el)
    el.querySelector('#consent-approve').addEventListener('click', () => decide(true))
    el.querySelector('#consent-deny').addEventListener('click', () => decide(false))
    return el
  }

  async function decide(approve) {
    if (!activeSession || busy) return
    busy = true
    const hint = document.getElementById('consent-hint')
    if (hint) hint.textContent = approve ? 'Approving…' : 'Denying…'
    try {
      await invoke(approve ? 'cmd_consent_approve' : 'cmd_consent_deny', { session: activeSession })
      hide()
    } catch (e) {
      if (hint) hint.textContent = 'Failed: ' + e
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
  const KINDS = {
    rc: {
      title: 'Remote control request',
      verb: 'is requesting to control this device',
    },
    exec: {
      title: 'Command execution request',
      verb: 'wants to run a command on this device',
    },
    ssh: {
      title: 'SSH session request',
      verb: 'wants to open an SSH session on this device',
    },
  }

  function show(pc) {
    const el = ensureModal()
    activeSession = pc.session_id
    const kind = KINDS[pc.kind] || KINDS.rc
    document.getElementById('consent-title').textContent = kind.title
    document.getElementById('consent-verb').textContent = kind.verb
    document.getElementById('consent-who').textContent = pc.controller_name || 'A remote operator'
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

  setInterval(poll, 1500)
  poll()
})()
