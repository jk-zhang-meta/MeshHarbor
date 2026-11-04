// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
/*
 * FR-27 — the session banner's logic.
 *
 * Reads live remote-control sessions from the daemon and offers a Disconnect
 * that takes the SAME teardown path as the native Windows overlay's button
 * (LocalAPI RcDisconnect -> the signalling loop's kill channel), rather than a
 * second, subtly different way to end a session.
 *
 * Every daemon-supplied string goes in with textContent: controller names come
 * from another machine.
 */
;(function () {
  const invoke = (name, payload) => window.__TAURI__.core.invoke(name, payload || {})
  const $ = (id) => document.getElementById(id)

  let sessions = []
  let busy = false

  function ago(startedAtMs) {
    if (!startedAtMs) return ''
    const secs = Math.max(0, Math.round((Date.now() - startedAtMs) / 1000))
    if (secs < 60) return `${secs}s`
    const mins = Math.round(secs / 60)
    return mins < 60 ? `${mins} min` : `${Math.round(mins / 60)} h`
  }

  function paint() {
    if (sessions.length === 0) {
      $('v-who').textContent = 'Being viewed'
      $('v-sub').textContent = ''
      $('v-rec-stop').hidden = true
      $('v-stop').hidden = false
      return
    }
    // FR-85 P3b — a controller RECORDING outranks one merely watching: it is
    // the first thing said, and the only way to stop it without ending the
    // session sits right here.
    const recorder = sessions.find((s) => s.recording)
    const first = recorder || sessions[0]
    const extra = sessions.length - 1
    const who = first.controller_name || 'a remote operator'
    $('v-who').textContent =
      (recorder ? `Recording your screen for ${who}` : `Being viewed by ${who}`) +
      (extra > 0 ? ` +${extra}` : '')
    $('v-rec-stop').hidden = !recorder
    // FR-85 P3b-3 — a recording whose session dropped goes on for up to a
    // minute while its controller reconnects. Say so, and keep only its Stop:
    // there is no session left to disconnect.
    $('v-stop').hidden = sessions.every((s) => s.reconnecting)
    if (first.reconnecting) {
      $('v-sub').textContent = 'reconnecting · it stops in a minute unless they come back'
      return
    }

    // The GRANT matters as much as the name: "watching" and "typing on this
    // machine" are different things to be told about.
    const perms = (first.permissions || '').toUpperCase()
    const typing = perms.includes('INPUT')
    const bits = [typing ? 'keyboard + mouse' : 'view only']
    if (first.org) bits.push(first.org)
    const age = ago(first.started_at_ms)
    if (age) bits.push(age)
    $('v-sub').textContent = bits.join(' · ')
  }

  async function poll() {
    try {
      const next = await invoke('cmd_rc_sessions')
      sessions = Array.isArray(next) ? next : []
    } catch (_) {
      // Daemon down: keep the last known text rather than blanking the strip.
      // The window is hidden by the watcher moments later anyway, and an
      // indicator that flickers to empty is worse than one that is briefly
      // stale.
      return
    }
    paint()
  }

  // FR-85 P3b — stop the RECORDING, keep the session: the file is kept, and
  // the controller is told the host stopped it (`host_stopped`).
  $('v-rec-stop').addEventListener('click', async () => {
    if (busy) return
    busy = true
    const btn = $('v-rec-stop')
    btn.disabled = true
    btn.textContent = 'Stopping…'
    try {
      await invoke('cmd_record_stop')
    } catch (e) {
      $('v-sub').textContent = 'Failed: ' + e
    } finally {
      busy = false
      btn.disabled = false
      btn.textContent = 'Stop recording'
    }
  })

  $('v-stop').addEventListener('click', async () => {
    if (busy || sessions.length === 0) return
    busy = true
    const btn = $('v-stop')
    btn.disabled = true
    btn.textContent = 'Stopping…'
    try {
      // Disconnect EVERY live session, not just the first. The button says
      // "Disconnect" next to "being viewed by X +2"; ending one of three and
      // leaving the strip up would read as a failure.
      for (const s of sessions) await invoke('cmd_rc_disconnect', { session: s.session_id })
    } catch (e) {
      $('v-sub').textContent = 'Failed: ' + e
    } finally {
      busy = false
      btn.disabled = false
      btn.textContent = 'Disconnect'
    }
  })

  setInterval(poll, 1000)
  poll()
})()
