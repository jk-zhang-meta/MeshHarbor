// SPDX-License-Identifier: AGPL-3.0-only
// The landing page in its two languages (2026-11-24).
import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import i18n, { setLocale } from '@/plugins/i18n'
import ArchitectureGraphic from '@/components/landing/ArchitectureGraphic.vue'
import {
  CAPABILITIES,
  HERO,
  PILLARS,
  landingCopy,
} from '@/utils/landing'

describe('the landing copy', () => {
  it('reads English for English and anything unknown, so the static homepage is unchanged', () => {
    for (const loc of ['en', 'fr', '']) {
      const c = landingCopy(loc)
      expect(c.HERO).toBe(HERO)
      expect(c.PILLARS).toBe(PILLARS)
      expect(c.CAPABILITIES).toBe(CAPABILITIES)
    }
  })

  it('reads Chinese for Chinese, with the same icons and colours in the same places', () => {
    const zh = landingCopy('zh-CN')
    expect(zh.HERO.titleLead).not.toBe(HERO.titleLead)
    expect(zh.CAPABILITIES).toHaveLength(CAPABILITIES.length)
    expect(zh.PILLARS).toHaveLength(PILLARS.length)
    zh.PILLARS.forEach((p, i) => {
      expect(p.features.map((f) => [f.icon, f.color])).toEqual(PILLARS[i]!.features.map((f) => [f.icon, f.color]))
      for (const f of p.features) expect(f.title).toMatch(/[一-鿿]/)
    })
  })
})

describe('the architecture graphic', () => {
  const vuetify = createVuetify({ components, directives })

  it('speaks the interface language', async () => {
    // jsdom has no matchMedia; reduced motion keeps the spotlight still.
    vi.stubGlobal('matchMedia', (q: string) => ({ matches: true, media: q, addEventListener() {}, removeEventListener() {} }))
    setLocale('zh-CN')
    try {
      const w = mount(ArchitectureGraphic, { global: { plugins: [vuetify] } })
      expect(w.text()).toContain('控制平面')
      expect(w.text()).toContain('加密组网')
      expect(w.text()).not.toContain('landing.arch')
      w.unmount()
    } finally {
      setLocale('en')
      vi.unstubAllGlobals()
    }
    expect(i18n.global.locale.value).toBe('en')
  })
})
