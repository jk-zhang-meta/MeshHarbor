// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-120 P5 — the tutorial's navigation brings the chapter into view. `<v-main>`
// is the page's scroller, not the window, so `window.scrollTo` moved nothing:
// on a phone the rail sits above the chapter, and a tap changed the content
// off-screen. The chapter is scrolled into view when it is below the fold or
// scrolled past; already in view, nothing moves.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createI18n } from 'vue-i18n'
import en from '@/locales/en.json'

const hoisted = vi.hoisted(() => ({ replace: vi.fn() }))
vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { tenantId: 't1' }, hash: '' }),
  useRouter: () => ({ replace: hoisted.replace }),
}))
vi.mock('@/stores/auth', () => ({ useAuthStore: () => ({ user: { id: 'u1' } }) }))
vi.mock('@/composables/useSnackbar', () => ({ useSnackbar: () => ({ showSuccess: vi.fn() }) }))
vi.mock('@/composables/useTutorialProgress', () => ({
  useTutorialProgress: () => ({ doneCount: 0, isDone: () => false, toggle: vi.fn(), reset: vi.fn() }),
}))

import TutorialView from '@/views/tutorial/TutorialView.vue'

const vuetify = createVuetify({ components, directives })
const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })

function mountView() {
  return mount(TutorialView, {
    attachTo: document.body,
    global: { plugins: [vuetify, i18n], stubs: { VideoFacade: true } },
  })
}

/** The chapter card, its top where a test puts it, and a spy on its scroll. */
function chapterAt(w: ReturnType<typeof mountView>, top: number) {
  const card = w.find('.tutorial-chapter').element as HTMLElement
  const scrollIntoView = vi.fn()
  card.scrollIntoView = scrollIntoView
  card.getBoundingClientRect = () => ({ top }) as DOMRect
  return scrollIntoView
}

describe('TutorialView — the chapter comes into view (FR-120 P5)', () => {
  beforeEach(() => {
    hoisted.replace.mockReset()
    // jsdom's default viewport: 1024 × 768, so "below the fold" is a top past 384.
    window.innerHeight = 768
  })

  it('scrolls the chapter into view when it sits below the rail (a phone)', async () => {
    const w = mountView()
    const scroll = chapterAt(w, 600)
    await w.findAll('.tutorial-rail .v-list-item')[2]!.trigger('click')
    expect(hoisted.replace).toHaveBeenCalledWith({ hash: expect.stringMatching(/^#/) })
    expect(scroll).toHaveBeenCalledWith({ behavior: 'smooth', block: 'start' })
    w.unmount()
  })

  it('scrolls the chapter back into view when the reader has scrolled past its top', async () => {
    const w = mountView()
    const scroll = chapterAt(w, -900)
    await w.findAll('.tutorial-rail .v-list-item')[1]!.trigger('click')
    expect(scroll).toHaveBeenCalledOnce()
    w.unmount()
  })

  it('does not move a chapter that is already in view', async () => {
    const w = mountView()
    const scroll = chapterAt(w, 120)
    await w.findAll('.tutorial-rail .v-list-item')[3]!.trigger('click')
    expect(hoisted.replace).toHaveBeenCalled()
    expect(scroll).not.toHaveBeenCalled()
    w.unmount()
  })
})
