// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect } from 'vitest'
import {
  NOT_APPLICABLE,
  hostOffers,
  hostReason,
  hostSpeaks,
  hostUnavailable,
  parseUnavailable,
} from '@/utils/hostUnavailable'

/**
 * FR-97 P0c — the device's own "not here", as the viewer reads it. The shape
 * is `AgentCaps.unavailable` in `crates/remote_control/src/models.rs`, locked
 * there by `unavailable_wire_shape_is_locked`; the codes are the ones
 * `with_honest_words` (`agents/meshharbord/src/encode/caps.rs`) sends.
 */
describe('hostUnavailable', () => {
  // As a P0c agent's row comes back from GET /tenant/{id}/agent.
  const mac = {
    audio: [],
    unavailable: {
      audio: {
        code: 'no-backend',
        reason: 'System-audio capture is not implemented on this OS yet, so this host sends no sound',
      },
      'clipboard-image-events': {
        code: 'not-watched',
        reason:
          'Copied images are not watched on this host, so they do not sync on their own: send or fetch one with the clipboard buttons',
      },
      sas: { code: NOT_APPLICABLE, reason: 'Ctrl+Alt+Del has no system meaning on macOS' },
    },
  }
  const linux = {
    unavailable: {
      sas: {
        code: 'keys-only',
        reason:
          'Ctrl+Alt+Del is sent as ordinary keys, and the desktop decides what they do: GNOME and KDE bind them to log out',
      },
    },
  }
  const windows = {
    unavailable: {
      sas: {
        code: 'keys-only',
        reason:
          'Ctrl+Alt+Del is sent as ordinary keys: apps on the desktop get it, but the Windows lock and sign-in screens do not',
      },
    },
  }
  const older = { audio: ['opus'] }

  it('reads what the device said, feature by feature', () => {
    expect(hostUnavailable(mac, 'audio')?.code).toBe('no-backend')
    expect(hostUnavailable(mac, 'clipboard-image-events')?.code).toBe('not-watched')
    expect(hostUnavailable(mac, 'clipboard')).toBeNull()
    expect(hostUnavailable(windows, 'sas')?.code).toBe('keys-only')
  })

  it('reads an agent before P0c, or no agent yet, as nothing said', () => {
    for (const caps of [older, null, undefined, {}]) {
      expect(hostUnavailable(caps, 'audio')).toBeNull()
      expect(hostReason(caps, 'sas')).toBeNull()
      expect(hostOffers(caps, 'sas')).toBe(true)
    }
  })

  it('hides a control only where the feature means nothing on that OS', () => {
    expect(hostOffers(mac, 'sas')).toBe(false)
    // A reason is not a refusal to show: Windows and Linux keep the button and
    // say what the keys reach there.
    expect(hostOffers(windows, 'sas')).toBe(true)
    expect(hostOffers(linux, 'sas')).toBe(true)
    expect(hostReason(linux, 'sas')).toMatch(/log out\.$/)
    expect(hostOffers(mac, 'audio')).toBe(true)
  })

  it("gives the device's reason as a sentence, and the code when it gave none", () => {
    expect(hostReason(mac, 'clipboard-image-events')).toBe(
      'Copied images are not watched on this host, so they do not sync on their own: send or fetch one with the clipboard buttons.',
    )
    const silent = { unavailable: { clipboard: { code: 'no-session', reason: '' } } }
    expect(hostReason(silent, 'clipboard')).toBe('Not available on this device (no-session).')
  })

  it('keeps a well-formed entry, a feature it does not know included, and drops the rest', () => {
    expect(
      parseUnavailable({
        audio: { code: 'no-backend', reason: 'r' },
        'some-future-feature': { code: 'x', reason: 'y' },
        clipboard: { code: '', reason: 'empty code' },
        sas: { reason: 'no code' },
        files: 'not an object',
        layout: ['nor', 'this'],
        input: { code: 'ok', reason: 42 },
      }),
    ).toEqual({
      audio: { code: 'no-backend', reason: 'r' },
      'some-future-feature': { code: 'x', reason: 'y' },
      input: { code: 'ok', reason: '' },
    })
    for (const raw of [null, undefined, 'x', 7, [], [{ code: 'a' }]]) {
      expect(parseUnavailable(raw)).toEqual({})
    }
  })

  it('caps a reason at a tooltip, not a page', () => {
    const long = 'a'.repeat(5000)
    expect(parseUnavailable({ audio: { code: 'c', reason: long } }).audio!.reason).toHaveLength(300)
  })

  // FR-97 P3e-2 — display match follows the device's word, and an agent from
  // before P0c, which says nothing at all, keeps the old gate.
  it('says whether the device speaks at all', () => {
    expect(hostSpeaks(null)).toBe(false)
    expect(hostSpeaks({})).toBe(false)
    expect(hostSpeaks({ unavailable: {} })).toBe(false)
    expect(hostSpeaks({ unavailable: { sas: { code: 'keys-only', reason: 'r' } } })).toBe(true)
    expect(hostSpeaks({ unavailable: { sas: { reason: 'no code' } } })).toBe(false)
  })

  it('reads a host whose display cannot be switched', () => {
    const caps = {
      unavailable: {
        sas: { code: 'keys-only', reason: 'Ctrl+Alt+Del is sent as ordinary keys' },
        'display-match': {
          code: 'unsupported',
          reason: "This host's display cannot be switched to your window",
        },
      },
    }
    expect(hostReason(caps, 'display-match')).toBe("This host's display cannot be switched to your window.")
    expect(hostReason({ unavailable: { sas: { code: 'keys-only', reason: 'r' } } }, 'display-match')).toBeNull()
  })
})
