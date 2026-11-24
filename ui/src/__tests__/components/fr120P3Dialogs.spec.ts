// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-120 P3 — the dialogs and title rows FR-116 didn't reach. Each dialog of
// substance below covers the screen below 600 px (`useResponsiveDialog`),
// scrolls its body, and carries its own named close: a full-screen dialog has
// no scrim to tap. A question that names a device wraps, because the name is
// the one thing to read before confirming; a title row with buttons wraps.
//
// The views that own most of these are too large to mount for one dialog
// each, so their templates are parsed and the structure is locked, as
// rcRatingMount.spec.ts does. GiphyPicker is mounted at 360 and 1024 px to
// prove the binding itself flips at 600 px.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parse as parseSfc } from '@vue/compiler-sfc'
import { NodeTypes, type ElementNode, type TemplateChildNode } from '@vue/compiler-dom'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

vi.mock('@/api/client', () => ({ api: { get: vi.fn() } }))

import GiphyPicker from '@/components/chat/GiphyPicker.vue'

// Vitest runs from `ui/` (where its config lives); under jsdom
// `import.meta.url` is not a `file:` URL, so the SFCs are resolved from there.
const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8')

function templateOf(path: string): ElementNode {
  const { descriptor } = parseSfc(read(path), { filename: path })
  expect(descriptor.template?.ast, `${path} has a template`).toBeTruthy()
  return descriptor.template!.ast as unknown as ElementNode
}

/** Every element under `node`, depth first. */
function walk(node: ElementNode | TemplateChildNode, visit: (el: ElementNode) => void): void {
  if (!('children' in node) || !Array.isArray(node.children)) return
  if (node.type === NodeTypes.ELEMENT) visit(node)
  for (const c of node.children as TemplateChildNode[]) walk(c, visit)
}

function below(el: ElementNode, pred: (e: ElementNode) => boolean): ElementNode[] {
  const out: ElementNode[] = []
  walk(el, (e) => {
    if (e !== el && pred(e)) out.push(e)
  })
  return out
}

/** A static attribute's value ('' when it has none), or a bound one's expression. */
function attr(el: ElementNode, name: string): string | null {
  for (const p of el.props) {
    if (p.type === NodeTypes.ATTRIBUTE && p.name === name) return p.value?.content ?? ''
    if (p.type === NodeTypes.DIRECTIVE && p.name === 'bind' && p.arg && 'content' in p.arg && p.arg.content === name) {
      return p.exp && 'content' in p.exp ? p.exp.content : ''
    }
  }
  return null
}

/** A directive's expression (`model`, `if`), or its argument for `slot`. */
function directive(el: ElementNode, name: string): string | null {
  for (const p of el.props) {
    if (p.type !== NodeTypes.DIRECTIVE || p.name !== name) continue
    if (name === 'slot') return p.arg && 'content' in p.arg ? p.arg.content : 'default'
    return p.exp && 'content' in p.exp ? p.exp.content : ''
  }
  return null
}

const classes = (el: ElementNode) => (attr(el, 'class') ?? '').split(/\s+/).filter(Boolean)

function dialog(path: string, model: string): ElementNode {
  const found: ElementNode[] = []
  walk(templateOf(path), (el) => {
    if (el.tag === 'v-dialog' && directive(el, 'model') === model) found.push(el)
  })
  expect(found, `${path}: one v-dialog with v-model="${model}"`).toHaveLength(1)
  return found[0]
}

const isClose = (e: ElementNode) =>
  e.tag === 'v-btn' &&
  (attr(e, 'icon') === 'mdi-close' ||
    below(e, (i) => i.tag === 'v-icon').some((i) =>
      i.children.some((t) => t.type === NodeTypes.TEXT && t.content.trim() === 'mdi-close'),
    ))

const AGENTS = 'src/components/admin/AgentsSection.vue'
const DIALOGS = [
  { file: AGENTS, model: 'evictDialogOpen', bound: 'fullscreen' },
  { file: AGENTS, model: 'updateAllDialogOpen', bound: 'fullscreen' },
  { file: AGENTS, model: 'deleteDialogOpen', bound: 'fullscreen' },
  { file: AGENTS, model: 'joinOrgDialogOpen', bound: 'fullscreen' },
  { file: AGENTS, model: 'routesDialogOpen', bound: 'fullscreen' },
  { file: 'src/components/admin/MembersSection.vue', model: 'rolesDialog', bound: 'fullscreen' },
  { file: 'src/components/chat/GiphyPicker.vue', model: 'open', bound: 'fullscreen' },
]

describe.each(DIALOGS)('$file, the dialog on $model (FR-120 P3)', ({ file, model, bound }) => {
  const d = dialog(file, model)

  it('covers the screen below 600 px, through useResponsiveDialog', () => {
    expect(attr(d, 'fullscreen')).toBe(bound)
    const binding = bound === 'fullscreen' ? '{ fullscreen }' : `{ fullscreen: ${bound} }`
    expect(read(file)).toContain(`const ${binding} = useResponsiveDialog()`)
  })

  it('scrolls its body, so its actions stay on screen', () => {
    expect(attr(d, 'scrollable')).not.toBeNull()
  })

  it('carries its own close, with a name', () => {
    const closes = below(d, isClose)
    expect(closes.length).toBeGreaterThan(0)
    expect(closes.some((c) => attr(c, 'aria-label'))).toBe(true)
  })
})

describe('a question that names a device wraps (FR-120 P3)', () => {
  it.each(['evictDialogOpen', 'rotateKeyDialogOpen'])('the dialog on %s', (model) => {
    const title = below(dialog(AGENTS, model), (e) => e.tag === 'v-card-title')[0]
    expect(title).toBeTruthy()
    const wraps = (e: ElementNode) => classes(e).includes('text-wrap')
    expect(wraps(title) || below(title, wraps).length > 0).toBe(true)
  })
})

describe('a title row with buttons wraps (FR-120 P3)', () => {
  // Overlay routes' title and device chip sit side by side, so the row gaps
  // both ways; Roles' title and button are parted by a spacer, so only its
  // lines gap — column gaps would wrap it at 360 px, where it fits.
  it.each([
    ['src/components/admin/OverlaySubnetRoutesSection.vue', 'ga-2'],
    ['src/components/admin/RolesSection.vue', 'gr-2'],
  ])('%s', (file, gap) => {
    const first = below(templateOf(file), (e) => e.tag === 'v-card-title')[0]
    expect(classes(first)).toEqual(expect.arrayContaining(['d-flex', 'flex-wrap', gap]))
  })
})

describe('GiphyPicker covers the screen below 600 px (FR-120 P3)', () => {
  let opened: ReturnType<typeof mount> | null = null
  // An overlay measures itself against the viewport; jsdom has neither of these.
  beforeEach(() => {
    vi.stubGlobal(
      'ResizeObserver',
      class {
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    )
    vi.stubGlobal('visualViewport', {
      width: 360,
      height: 780,
      offsetLeft: 0,
      offsetTop: 0,
      pageLeft: 0,
      pageTop: 0,
      scale: 1,
      addEventListener() {},
      removeEventListener() {},
    })
  })
  afterEach(() => {
    opened?.unmount()
    opened = null
    window.innerWidth = 1024
    vi.unstubAllGlobals()
  })

  /** Vuetify reads the window's width when the plugin is made. */
  async function openAt(width: number) {
    window.innerWidth = width
    const vuetify = createVuetify({ components, directives })
    opened = mount(GiphyPicker, { props: { modelValue: true }, global: { plugins: [vuetify] }, attachTo: document.body })
    await flushPromises()
    return document.body.querySelector('.v-dialog.v-overlay--active') as HTMLElement | null
  }

  it('at 360 px', async () => {
    const d = await openAt(360)
    expect(d?.classList.contains('v-dialog--fullscreen')).toBe(true)
    expect(d?.querySelector('.v-card-title [aria-label="Close"]')).toBeTruthy()
  })

  it('and stays a centred card at 1024 px', async () => {
    const d = await openAt(1024)
    expect(d).toBeTruthy()
    expect(d?.classList.contains('v-dialog--fullscreen')).toBe(false)
  })
})
