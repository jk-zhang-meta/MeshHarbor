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
  FALLBACK_PLANS,
  HERO,
  PILLARS,
  annualLine,
  landingCopy,
  planFeature,
  planName,
  type Plan,
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

  it('has a Chinese line for every plan line and name the page can show before the server answers', () => {
    for (const plan of FALLBACK_PLANS) {
      expect(planName(plan, 'zh-CN')).not.toBe(plan.name)
      for (const line of plan.features) expect(planFeature(line, 'zh-CN'), line).not.toBe(line)
    }
  })

  it('keeps a line it does not know as the server sent it, and English as it is', () => {
    expect(planFeature('A new line from a newer server', 'zh-CN')).toBe('A new line from a newer server')
    expect(planFeature('10 users', 'en')).toBe('10 users')
    expect(planName({ id: 'team', name: 'Team', price_cents: 0, features: [] }, 'zh-CN')).toBe('Team')
  })

  it('says the annual price in the page language', () => {
    const pro: Plan = {
      ...FALLBACK_PLANS[1]!,
      prices: [{ interval: 'year', currency: 'usd', unit_amount: 8000 }],
    }
    expect(annualLine(pro)).toBe('or $80 per user per year (two months free)')
    expect(annualLine(pro, 'zh-CN')).toBe('或 $80 每用户每年（相当于送两个月）')
    expect(annualLine(FALLBACK_PLANS[0]!, 'zh-CN')).toBeNull()
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
