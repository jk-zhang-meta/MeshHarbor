// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { createI18n } from 'vue-i18n'
import { en as vuetifyEn, zhHans as vuetifyZh } from 'vuetify/locale'
import en from '@/locales/en.json'
import zhCN from '@/locales/zh-CN.json'

/** The languages a person can pick. English is the default; a key missing from a
 *  translation falls back to English, never to a raw key. */
export const LOCALES = [
  { code: 'en', label: 'English' },
  { code: 'zh-CN', label: '中文（简体）' },
] as const
export type LocaleCode = (typeof LOCALES)[number]['code']
const STORAGE_KEY = 'meshharbor.locale'

function isLocale(v: unknown): v is LocaleCode {
  return LOCALES.some((l) => l.code === v)
}

/** The remembered choice; storage can be absent or throw (private mode, previews). */
function initialLocale(): LocaleCode {
  try {
    const saved = globalThis.localStorage?.getItem(STORAGE_KEY)
    if (isLocale(saved)) return saved
  } catch {
    /* fall through to the default */
  }
  return 'en'
}

const i18n = createI18n({
  legacy: false,
  locale: 'en',
  fallbackLocale: 'en',
  messages: { en: { ...en, $vuetify: vuetifyEn } },
})
// Registered after creation so the instance keeps the plain `string` locale type Vuetify's
// adapter expects (a literal two-locale map narrows it and breaks the adapter's typing).
;(i18n.global as unknown as { setLocaleMessage(locale: string, messages: unknown): void }).setLocaleMessage(
  'zh-CN',
  { ...zhCN, $vuetify: vuetifyZh },
)
;(i18n.global.locale as unknown as { value: string }).value = initialLocale()

/** Switch the interface language and remember it on this browser. */
export function setLocale(code: LocaleCode) {
  if (!isLocale(code)) return
  ;(i18n.global.locale as unknown as { value: string }).value = code
  try {
    globalThis.localStorage?.setItem(STORAGE_KEY, code)
  } catch {
    /* the choice still applies to this page */
  }
  if (typeof document !== 'undefined') document.documentElement.lang = code
}

if (typeof document !== 'undefined') document.documentElement.lang = initialLocale()

export default i18n
