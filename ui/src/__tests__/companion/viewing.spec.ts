// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * meshharbor-desktop's "being viewed" banner (FR-27), and what FR-85 P3b adds to
 * it: a controller RECORDING the screen is the first thing it says, with a
 * Stop that ends the recording and keeps the session.
 *
 * Driven by the REAL `panel-viewing.html` body and `panel-viewing.js`, in
 * jsdom, against a mocked Tauri `invoke` — the same approach as the
 * Recordings view's spec.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const FRONT = join(HERE, '..', '..', '..', '..', 'agents', 'meshharbor-desktop', 'src', 'front')
const HTML = readFileSync(join(FRONT, 'panel-viewing.html'), 'utf8')
const SCRIPT = readFileSync(join(FRONT, 'panel-viewing.js'), 'utf8')

type Invoke = (name: string, payload?: Record<string, unknown>) => Promise<unknown>

function mount(invoke: Invoke) {
  const parsed = new DOMParser().parseFromString(HTML, 'text/html')
  document.body.innerHTML = ''
  // The body's children only: the script is evaluated below, not by jsdom.
  for (const n of Array.from(parsed.body.childNodes)) {
    if (n.nodeName !== 'SCRIPT') document.body.appendChild(document.importNode(n, true))
  }
  ;(window as unknown as Record<string, unknown>).__TAURI__ = { core: { invoke } }
  window.eval(SCRIPT)
}

const $ = (id: string) => document.getElementById(id) as HTMLElement
const settle = () => vi.advanceTimersByTimeAsync(0)

const session = (over: Record<string, unknown> = {}) => ({
  session_id: '66f0c0ffee0000000000abcd',
  controller_name: 'Alice',
  permissions: 'VIEW | INPUT',
  started_at_ms: 0,
  ...over,
})

describe('companion viewing banner (FR-27, FR-85 P3b)', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.clearAllTimers()
    vi.useRealTimers()
  })

  it('says who is watching, and offers no recording stop when nobody records', async () => {
    mount(vi.fn(async () => [session()]))
    await settle()
    expect($('v-who').textContent).toBe('Being viewed by Alice')
    expect($('v-rec-stop').hidden).toBe(true)
  })

  it('leads with a RECORDING controller, even when another viewer came first', async () => {
    mount(
      vi.fn(async () => [
        session({ session_id: 'a', controller_name: 'Bob' }),
        session({ session_id: 'b', controller_name: 'Alice', recording: true }),
      ]),
    )
    await settle()
    expect($('v-who').textContent).toBe('Recording your screen for Alice +1')
    expect($('v-rec-stop').hidden).toBe(false)
  })

  it('stops the recording, not the session', async () => {
    const invoke = vi.fn(async (name: string) =>
      name === 'cmd_rc_sessions' ? [session({ recording: true })] : undefined,
    )
    mount(invoke)
    await settle()
    $('v-rec-stop').click()
    await settle()
    expect(invoke).toHaveBeenCalledWith('cmd_record_stop', {})
    expect(invoke).not.toHaveBeenCalledWith('cmd_rc_disconnect', expect.anything())
  })

  it('takes the recording notice down when the recording ends', async () => {
    let recording = true
    mount(vi.fn(async () => [session({ recording })]))
    await settle()
    expect($('v-rec-stop').hidden).toBe(false)
    recording = false
    await vi.advanceTimersByTimeAsync(1000)
    expect($('v-rec-stop').hidden).toBe(true)
    expect($('v-who').textContent).toBe('Being viewed by Alice')
  })

  it('keeps saying a dropped session’s recording goes on, with its Stop and no Disconnect (P3b-3)', async () => {
    mount(vi.fn(async () => [session({ recording: true, reconnecting: true })]))
    await settle()
    expect($('v-who').textContent).toBe('Recording your screen for Alice')
    expect($('v-sub').textContent).toContain('reconnecting')
    expect($('v-rec-stop').hidden).toBe(false)
    // No session is left to disconnect.
    expect($('v-stop').hidden).toBe(true)
  })

  it('offers Disconnect again while another session is live beside it (P3b-3)', async () => {
    mount(
      vi.fn(async () => [
        session({ session_id: 'a', recording: true, reconnecting: true }),
        session({ session_id: 'b', controller_name: 'Bob' }),
      ]),
    )
    await settle()
    expect($('v-rec-stop').hidden).toBe(false)
    expect($('v-stop').hidden).toBe(false)
  })
})
