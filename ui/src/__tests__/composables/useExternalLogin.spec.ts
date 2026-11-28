// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect } from 'vitest'
import { friendlyExtauthRefusal } from '@/composables/useExternalLogin'

describe('FR-115 P3b: an external session refused by the slot count', () => {
  it('says the org is at its session limit, and how past it', () => {
    const text = friendlyExtauthRefusal('session_limit')
    expect(text).toContain('concurrent remote session limit')
    expect(text).toContain('connect for another organization')
  })

  it('keeps the coarse answers it had', () => {
    expect(friendlyExtauthRefusal('unavailable')).toContain('not available for outside access')
    expect(friendlyExtauthRefusal('something-newer')).toBe('The device refused the request.')
  })
})
