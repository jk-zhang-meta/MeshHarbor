// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-58 — the deferred landing auto-ask. The load-bearing behaviors: it shows
// once ever (latch), only after the deferral, and UNREADABLE storage means
// "never show" — failing toward not annoying, because a prompt we can't
// remember having shown must not become a prompt on every visit.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

vi.mock('@/api/client', () => ({
  api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
}))

import NewsletterPrompt from '@/components/landing/NewsletterPrompt.vue'

const vuetify = createVuetify({ components, directives })

// Default stubs on purpose: test-utils stubs <transition> wrappers, which is
// what lets the v-if content appear synchronously in jsdom. Un-stubbing the
// real Vuetify slide transition leaves the card permanently un-inserted here.
function mountPrompt() {
  return mount(NewsletterPrompt, {
    global: {
      plugins: [vuetify],
      stubs: { RouterLink: true },
    },
  })
}

describe('NewsletterPrompt', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('stays hidden before the deferral, then shows after ~20s', async () => {
    const w = mountPrompt()
    expect(w.find('.newsletter-prompt').exists()).toBe(false)
    vi.advanceTimersByTime(21_000)
    await w.vm.$nextTick()
    expect(w.find('.newsletter-prompt').exists()).toBe(true)
  })

  it('never shows again after a dismissal — the latch is forever', async () => {
    const w = mountPrompt()
    vi.advanceTimersByTime(21_000)
    await w.vm.$nextTick()
    await w.find('.prompt-close').trigger('click')
    expect(w.find('.newsletter-prompt').exists()).toBe(false)
    expect(localStorage.getItem('meshharbor-newsletter-dismissed')).not.toBeNull()

    const again = mountPrompt()
    vi.advanceTimersByTime(60_000)
    await again.vm.$nextTick()
    expect(again.find('.newsletter-prompt').exists()).toBe(false)
  })

  it('treats UNREADABLE storage as already-dismissed', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('storage disabled')
    })
    const w = mountPrompt()
    vi.advanceTimersByTime(60_000)
    await w.vm.$nextTick()
    expect(
      w.find('.newsletter-prompt').exists(),
      'a prompt we cannot remember having shown must not show at all',
    ).toBe(false)
  })

  it('subscribing latches too — the answer is the answer', async () => {
    const w = mountPrompt()
    vi.advanceTimersByTime(21_000)
    await w.vm.$nextTick()
    const stay = w.findComponent({ name: 'StayInTouch' })
    stay.vm.$emit('subscribed')
    await w.vm.$nextTick()
    expect(localStorage.getItem('meshharbor-newsletter-dismissed')).not.toBeNull()
  })
})
