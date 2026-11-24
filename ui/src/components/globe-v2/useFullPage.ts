// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// Full-page overlay state machine (S9 / AC11):
// - Primary mechanism: <Teleport to="body" :disabled="!isFull"> fixed 100dvh overlay
//   (works on iPhone Safari where Fullscreen API is unavailable for non-video elements).
// - Locks body scroll, marks #app inert while open, pushes ?g_full=1 history entry
//   for browser Back exit, handles Esc exit, and restores focus to trigger button.
// - Progressive enhancement: optional Fullscreen API when document.fullscreenEnabled.

import { nextTick, onBeforeUnmount, onMounted, ref, type Ref } from 'vue'

export interface UseFullPageOptions {
  containerRef: Ref<HTMLElement | null>
  triggerRef?: Ref<HTMLElement | null>
  onToggle?: (full: boolean) => void
}

export function useFullPage(options: UseFullPageOptions) {
  const isFull = ref(false)
  const isNativeFullscreen = ref(false)
  const fullscreenSupported = ref(
    typeof document !== 'undefined' && Boolean(document.fullscreenEnabled),
  )

  let pushedHistory = false
  let prevOverflow = ''

  function setAppInert(inert: boolean): void {
    if (typeof document === 'undefined') return
    const appEl = document.getElementById('app') as (HTMLElement & { inert?: boolean }) | null
    if (appEl) {
      appEl.inert = inert
    }
  }

  async function enterFullPage(): Promise<void> {
    if (isFull.value) return
    isFull.value = true
    if (typeof document !== 'undefined') {
      prevOverflow = document.body.style.overflow
      document.body.style.overflow = 'hidden'
      setAppInert(true)
    }
    if (typeof window !== 'undefined' && window.history?.pushState) {
      const url = new URL(window.location.href)
      if (url.searchParams.get('g_full') !== '1') {
        url.searchParams.set('g_full', '1')
        window.history.pushState({ ...(window.history.state ?? {}), mhGlobeFull: true }, '', url.toString())
        pushedHistory = true
      }
    }
    options.onToggle?.(true)
    await nextTick()
  }

  async function exitFullPage(fromPopstate = false): Promise<void> {
    if (!isFull.value) return
    if (typeof document !== 'undefined' && document.fullscreenElement) {
      try {
        await document.exitFullscreen()
      } catch {
        /* ignore */
      }
    }
    isFull.value = false
    if (typeof document !== 'undefined') {
      document.body.style.overflow = prevOverflow
      setAppInert(false)
    }
    if (pushedHistory && !fromPopstate && typeof window !== 'undefined') {
      pushedHistory = false
      const url = new URL(window.location.href)
      if (url.searchParams.get('g_full') === '1') {
        url.searchParams.delete('g_full')
        window.history.replaceState(window.history.state, '', url.toString())
      }
    } else {
      pushedHistory = false
    }
    options.onToggle?.(false)
    await nextTick()
    options.triggerRef?.value?.focus?.()
  }

  function toggleFullPage(): void {
    if (isFull.value) void exitFullPage(false)
    else void enterFullPage()
  }

  async function toggleNativeFullscreen(): Promise<void> {
    if (!fullscreenSupported.value || typeof document === 'undefined') return
    if (document.fullscreenElement) {
      try {
        await document.exitFullscreen()
      } catch {
        /* ignore */
      }
      return
    }
    if (!isFull.value) {
      await enterFullPage()
    }
    const el = options.containerRef.value
    if (el && el.requestFullscreen) {
      try {
        await el.requestFullscreen({ navigationUI: 'hide' })
      } catch {
        /* browser may reject without user gesture */
      }
    }
  }

  function handlePopstate(): void {
    if (!isFull.value) return
    const url = new URL(window.location.href)
    if (url.searchParams.get('g_full') !== '1') {
      void exitFullPage(true)
    }
  }

  function handleFullscreenChange(): void {
    if (typeof document === 'undefined') return
    isNativeFullscreen.value = Boolean(document.fullscreenElement)
  }

  onMounted(() => {
    if (typeof window !== 'undefined') {
      window.addEventListener('popstate', handlePopstate)
    }
    if (typeof document !== 'undefined') {
      document.addEventListener('fullscreenchange', handleFullscreenChange)
    }
  })

  onBeforeUnmount(() => {
    if (typeof window !== 'undefined') {
      window.removeEventListener('popstate', handlePopstate)
    }
    if (typeof document !== 'undefined') {
      document.removeEventListener('fullscreenchange', handleFullscreenChange)
      if (isFull.value) {
        document.body.style.overflow = prevOverflow
        setAppInert(false)
      }
    }
  })

  return {
    isFull,
    isNativeFullscreen,
    fullscreenSupported,
    enterFullPage,
    exitFullPage,
    toggleFullPage,
    toggleNativeFullscreen,
  }
}
