// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, describe, expect, it } from 'vitest'
import i18n, { LOCALES, setLocale } from '@/plugins/i18n'
import en from '@/locales/en.json'
import zhCN from '@/locales/zh-CN.json'

type Tree = { [k: string]: string | Tree }
function leaves(tree: Tree, prefix = ''): string[] {
  return Object.entries(tree).flatMap(([k, v]) => (typeof v === 'string' ? [prefix + k] : leaves(v, `${prefix}${k}.`)))
}
const t = (key: string) => i18n.global.t(key)

afterEach(() => setLocale('en'))

describe('interface language', () => {
  it('defaults to English and offers Chinese as the alternative', () => {
    expect(String(i18n.global.locale.value)).toBe('en')
    expect(LOCALES.map((l) => l.code)).toEqual(['en', 'zh-CN'])
    expect(t('mh.nav.deviceShares')).toBe('Device shares')
  })

  it('switches, remembers the choice on this browser, and marks the document language', () => {
    setLocale('zh-CN')
    expect(t('mh.nav.deviceShares')).toBe('设备分享')
    expect(localStorage.getItem('meshharbor.locale')).toBe('zh-CN')
    expect(document.documentElement.lang).toBe('zh-CN')
  })

  it('falls back to English for a string the translation lacks, never to a raw key', () => {
    setLocale('zh-CN')
    expect(t('room.create')).toBe('Create Room')
  })

  it('translates every MeshHarbor management string', () => {
    const mh = leaves((en as unknown as Tree).mh as Tree, 'mh.')
    const zh = new Set(leaves((zhCN as unknown as Tree).mh as Tree, 'mh.'))
    expect(mh.length).toBeGreaterThan(100)
    expect(mh.filter((k) => !zh.has(k))).toEqual([])
  })
})
