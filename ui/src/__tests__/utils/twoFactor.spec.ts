// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-129 — the browser's rules for a device that asks for a code.
import { afterEach, describe, expect, it } from 'vitest'
import { setLocale } from '@/plugins/i18n'
import {
  asksForCode,
  asTwoFactorRefusal,
  codeForWire,
  formatWait,
  groupKey,
  normalizeCode,
  recoveryCodesFile,
  supportsTwoFactor,
  twoFactorOn,
  twoFactorRefusalOfExecError,
  twoFactorRefusalText,
  ungroupKey,
} from '@/utils/twoFactor'

afterEach(() => setLocale('en'))

describe('FR-129 two-factor capability', () => {
  it('needs the exact verb, never a prefix or a neighbour', () => {
    expect(supportsTwoFactor({ rpc: ['exec', 'two-factor'] })).toBe(true)
    expect(supportsTwoFactor({ rpc: ['two-factor-v2'] })).toBe(false)
    expect(supportsTwoFactor({ rpc: ['two'] })).toBe(false)
    expect(supportsTwoFactor({ rpc: [] })).toBe(false)
    expect(supportsTwoFactor({})).toBe(false)
    expect(supportsTwoFactor(undefined)).toBe(false)
  })

  it('reads it as on only when the device says true', () => {
    expect(twoFactorOn({ two_factor: true })).toBe(true)
    expect(twoFactorOn({ two_factor: false })).toBe(false)
    expect(twoFactorOn({})).toBe(false)
    expect(twoFactorOn(null)).toBe(false)
  })
})

describe('FR-129 setup key', () => {
  it('groups the key in fours for typing, and copies it whole', () => {
    expect(groupKey('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')).toBe(
      'JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP',
    )
    expect(groupKey('ABCDEF')).toBe('ABCD EF')
    expect(groupKey('')).toBe('')
    expect(ungroupKey('JBSW Y3DP EHPK')).toBe('JBSWY3DPEHPK')
    expect(ungroupKey(groupKey('JBSWY3DPEHPK3PXPQ'))).toBe('JBSWY3DPEHPK3PXPQ')
  })
})

describe('FR-129 a typed code', () => {
  it('reads a 6-digit code with spaces or dashes', () => {
    expect(normalizeCode(' 123 456 ')).toBe('123456')
    expect(codeForWire('123456')).toBe('123456')
    expect(codeForWire('123 456')).toBe('123456')
    expect(codeForWire('123-456')).toBe('123456')
  })

  it('sends a recovery code as abcd-efgh, and only where one is allowed', () => {
    expect(codeForWire('ABCD-EFGH')).toBe('abcd-efgh')
    expect(codeForWire('abcdefgh')).toBe('abcd-efgh')
    // Confirming the app setup proves the app works: a recovery code there is not one.
    expect(codeForWire('abcd-efgh', false)).toBeNull()
    expect(codeForWire('123456', false)).toBe('123456')
  })

  it('refuses anything else before it costs one of the tries', () => {
    for (const bad of ['', '12345', '1234567', 'abc', 'abcd-efg', '12345a', 'abcd-efgh-ijkl']) {
      expect(codeForWire(bad)).toBeNull()
    }
  })
})

describe('FR-129 refusals', () => {
  it('classifies the device words by equality', () => {
    expect(asTwoFactorRefusal('two_factor_required')).toBe('two_factor_required')
    expect(asTwoFactorRefusal('two_factor_invalid')).toBe('two_factor_invalid')
    expect(asTwoFactorRefusal('two_factor_locked')).toBe('two_factor_locked')
    expect(asTwoFactorRefusal('two_factor_unavailable')).toBe('two_factor_unavailable')
    expect(asTwoFactorRefusal('two_factor')).toBeNull()
    expect(asTwoFactorRefusal('two_factor_required_x')).toBeNull()
    expect(asTwoFactorRefusal('user_denied')).toBeNull()
    expect(asTwoFactorRefusal(undefined)).toBeNull()
  })

  it('reads an exec refusal from the start of the result error', () => {
    expect(twoFactorRefusalOfExecError('two_factor_invalid: the two-factor code is wrong')).toBe(
      'two_factor_invalid',
    )
    expect(
      twoFactorRefusalOfExecError('two_factor_locked: too many wrong two-factor codes; try again in 60 s'),
    ).toBe('two_factor_locked')
    expect(twoFactorRefusalOfExecError('two_factor_required')).toBe('two_factor_required')
    // Somewhere else in the sentence, or another word, is not a refusal.
    expect(twoFactorRefusalOfExecError('device_disabled: two_factor_required')).toBeNull()
    expect(twoFactorRefusalOfExecError('two_factor_requiredx: nope')).toBeNull()
    expect(twoFactorRefusalOfExecError(null)).toBeNull()
    expect(twoFactorRefusalOfExecError('')).toBeNull()
  })

  it('asks for a fresh code only when one could help', () => {
    expect(asksForCode('two_factor_required')).toBe(true)
    expect(asksForCode('two_factor_invalid')).toBe(true)
    expect(asksForCode('two_factor_locked')).toBe(false)
    expect(asksForCode('two_factor_unavailable')).toBe(false)
    expect(asksForCode(null)).toBe(false)
  })

  it('words each refusal, with the wait when the device gave one', () => {
    expect(twoFactorRefusalText('two_factor_invalid')).toMatch(/wrong, expired or already used/)
    expect(twoFactorRefusalText('two_factor_locked')).toMatch(/try again later/)
    expect(twoFactorRefusalText('two_factor_locked', { retryAfterSecs: 45 })).toMatch(/in 45 s/)
    expect(twoFactorRefusalText('two_factor_locked', { retryAfterSecs: 900 })).toMatch(/in 15 min/)
    expect(twoFactorRefusalText('no_pending')).toMatch(/Start again/)
    expect(twoFactorRefusalText('not_primary')).toMatch(/primary organization/)
    // A word this page does not know: the device's own sentence.
    expect(twoFactorRefusalText('brand_new', { message: 'the device said so' })).toBe('the device said so')
    expect(twoFactorRefusalText('brand_new')).toBe('The device did not accept this step.')
  })

  it('speaks the interface language', () => {
    setLocale('zh-CN')
    expect(twoFactorRefusalText('two_factor_required')).toBe('此设备每次连接都需要两步验证码。')
    expect(formatWait(120)).toBe('2 分钟')
  })
})

describe('FR-129 recovery codes file', () => {
  it('lists every code under a header naming the device', () => {
    const text = recoveryCodesFile('GPU box', ['abcd-efgh', 'jkmn-pqrs'], new Date('2026-11-23T10:00:00Z'))
    const lines = text.split('\n')
    expect(lines[0]).toBe('MeshHarbor two-factor recovery codes')
    expect(lines[1]).toBe('Device: GPU box')
    expect(lines[2]).toBe('Created: 2026-11-23T10:00:00.000Z')
    expect(lines).toContain('abcd-efgh')
    expect(lines).toContain('jkmn-pqrs')
  })
})
