// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-131 P3 — the composable's own sentences reach the viewer in the reader's
// language, and a reworded one cannot silently fall back to English.
import { afterEach, describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import i18n, { setLocale } from '@/plugins/i18n'
import { RC_LITERALS, RC_PATTERNS, rcSays } from '@/composables/rcSays'
import {
  EXTERNAL_LOGIN_GONE,
  ZONE_REQUIRES_MESH_CONTROLLER,
  friendlyEndReason,
  friendlyRcError,
  mediaWaitingCopy,
} from '@/composables/useRemoteControl'

const t = (key: string, named?: Record<string, unknown>) =>
  named ? i18n.global.t(key, named) : i18n.global.t(key)
const composable = readFileSync(resolve(process.cwd(), 'src/composables/useRemoteControl.ts'), 'utf8')

afterEach(() => setLocale('en'))

describe('rcSays — the composable’s sentences, translated', () => {
  it('every literal it knows is still in the composable, word for word', () => {
    for (const text of Object.keys(RC_LITERALS)) {
      const quoted = [`'${text}'`, `"${text}"`, `\`${text}\``]
      expect(quoted.some((q) => composable.includes(q)), text).toBe(true)
    }
    for (const p of RC_PATTERNS) expect(composable.includes(`\`${p.source}\``), p.source).toBe(true)
  })

  it('reads the same in English, and in Chinese where it knows the words', () => {
    expect(rcSays('connection timed out', t)).toBe('connection timed out')
    expect(rcSays(EXTERNAL_LOGIN_GONE, t)).toBe(EXTERNAL_LOGIN_GONE)
    setLocale('zh-CN')
    expect(rcSays('connection timed out', t)).toBe('连接超时')
    expect(rcSays(ZONE_REQUIRES_MESH_CONTROLLER, t)).toBe(ZONE_REQUIRES_MESH_CONTROLLER)
    expect(rcSays(EXTERNAL_LOGIN_GONE, t)).toMatch(/[一-龥]/)
  })

  it('fills a pattern’s numbers in', () => {
    const notice = 'No video from this device after 3 attempts — retrying every 8s. Its network may be blocking the connection.'
    expect(rcSays(notice, t)).toBe(notice)
    setLocale('zh-CN')
    expect(rcSays(notice, t)).toBe('试了 3 次都没收到这台设备的画面，每 8 秒重试一次。它所在的网络可能挡住了连接。')
  })

  it('gives the zone advisory an English reading (the constant itself is Chinese)', () => {
    expect(rcSays(ZONE_REQUIRES_MESH_CONTROLLER, t)).toMatch(/^This device is in a different network zone/)
  })

  it('shows anything it does not know as it came: the server’s or the device’s own words', () => {
    setLocale('zh-CN')
    expect(rcSays('the device said something new', t)).toBe('the device said something new')
    expect(rcSays(null, t)).toBe('')
  })
})

describe('the composable’s pure helpers speak the reader’s language', () => {
  it('end reasons, rc:error codes and the waiting overlay', () => {
    setLocale('zh-CN')
    expect(friendlyEndReason('user_denied')).toBe('设备前的人拒绝了请求。')
    expect(friendlyRcError('agent_offline', null)).toMatch(/离线/)
    expect(mediaWaitingCopy('host_sleep').title).toBe('这台电脑正在进入睡眠。')
    setLocale('en')
    expect(friendlyEndReason('user_denied')).toBe('Someone at that device declined the request.')
  })
})
