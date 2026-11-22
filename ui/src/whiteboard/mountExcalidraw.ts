// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-126 P2 — Excalidraw (MIT) inside the Vue meeting view: a React island, loaded only when
// someone opens the whiteboard, so React and Excalidraw never reach the main bundle.
//
// The fonts are served from this origin (`excalidraw-assets/`, copied by vite.config.ts): the
// CSP allows fonts from 'self' only, and Excalidraw would otherwise fetch them from a CDN.
// The caller sets `window.EXCALIDRAW_ASSET_PATH` before importing this module.
import { createElement } from 'react'
import { createRoot } from 'react-dom/client'
import { CaptureUpdateAction, Excalidraw, reconcileElements } from '@excalidraw/excalidraw'
import type {
  ExcalidrawImperativeAPI,
  ExcalidrawInitialDataState,
} from '@excalidraw/excalidraw/types'
import '@excalidraw/excalidraw/index.css'

type Remote = Parameters<typeof reconcileElements>[1]

export interface BoardHandle {
  /** Apply elements that came from the meeting. */
  applyRemote(elements: readonly unknown[]): void
  /** Every element on this board, deleted ones included. */
  elements(): readonly unknown[]
  destroy(): void
}

export interface MountOptions {
  initialElements: readonly unknown[]
  langCode: string
  theme: 'light' | 'dark'
  /** Called on every change with the whole scene, deleted elements included. */
  onChange(elements: readonly unknown[]): void
}

export function mountExcalidraw(el: HTMLElement, opts: MountOptions): BoardHandle {
  let api: ExcalidrawImperativeAPI | null = null
  const queued: (readonly unknown[])[] = []
  const apply = (remote: readonly unknown[]) => {
    if (!api) {
      queued.push(remote)
      return
    }
    const merged = reconcileElements(
      api.getSceneElementsIncludingDeleted(),
      remote as unknown as Remote,
      api.getAppState(),
    )
    api.updateScene({ elements: merged, captureUpdate: CaptureUpdateAction.NEVER })
  }
  const root = createRoot(el)
  root.render(
    createElement(Excalidraw, {
      excalidrawAPI: (a: ExcalidrawImperativeAPI) => {
        api = a
        for (const q of queued.splice(0)) apply(q)
      },
      initialData: {
        elements: opts.initialElements as unknown as ExcalidrawInitialDataState['elements'],
        appState: { viewBackgroundColor: '#ffffff' },
        scrollToContent: true,
      },
      onChange: (elements: readonly unknown[]) =>
        opts.onChange(api ? api.getSceneElementsIncludingDeleted() : elements),
      langCode: opts.langCode,
      theme: opts.theme,
      UIOptions: {
        tools: { image: false },
        canvasActions: { loadScene: false, saveToActiveFile: false },
      },
    }),
  )
  return {
    applyRemote: apply,
    elements: () => (api ? api.getSceneElementsIncludingDeleted() : []),
    destroy: () => root.unmount(),
  }
}
