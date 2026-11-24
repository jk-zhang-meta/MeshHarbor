// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-120 P4b — the rest of the lists that ran long on a phone (FR-120 §2.2):
//
// - Members, Invites and Files are a `v-data-table-server` with `:mobile="xs"`,
//   which stacked every column of every row (~250–290 px a row). On a phone
//   each row is now one line, what decides plus at most one action, and a tap
//   opens the rest. Their templates are parsed and the phone row's structure is
//   locked (the three views are too large to mount for one row each);
// - the usage panel's Calls and Tunnel sessions and the keep-busy history are
//   `table-stack-xs` cards, each value labelled, and keep-busy's source chip
//   explains itself on a tap (FactChip);
// - the agent log shows its newest 200 lines on a phone, then 200 more;
// - the room tree gets a search, mounted here.
import { describe, expect, it, vi, beforeEach, afterEach, beforeAll } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parse as parseSfc } from '@vue/compiler-sfc'
import { NodeTypes, type ElementNode, type TemplateChildNode } from '@vue/compiler-dom'
import { setActivePinia, createPinia } from 'pinia'
import { mount, flushPromises } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

const read = (path: string) => readFileSync(resolve(process.cwd(), path), 'utf8')

function templateOf(path: string): ElementNode {
  const { descriptor } = parseSfc(read(path), { filename: path })
  return descriptor.template!.ast as unknown as ElementNode
}
function walk(node: ElementNode | TemplateChildNode, visit: (el: ElementNode) => void): void {
  if (!('children' in node) || !Array.isArray(node.children)) return
  if (node.type === NodeTypes.ELEMENT) visit(node)
  for (const c of node.children as TemplateChildNode[]) walk(c, visit)
}
function all(el: ElementNode): ElementNode[] {
  const out: ElementNode[] = []
  walk(el, (e) => out.push(e))
  return out
}
/** A bound attribute's expression, a static one's value, or a directive's expression. */
function attr(el: ElementNode, name: string): string | null {
  for (const p of el.props) {
    if (p.type === NodeTypes.ATTRIBUTE && p.name === name) return p.value?.content ?? ''
    if (p.type === NodeTypes.DIRECTIVE) {
      const arg = p.arg && 'content' in p.arg ? p.arg.content : null
      const exp = p.exp && 'content' in p.exp ? p.exp.content : ''
      if (p.name === 'bind' && arg === name) return exp
      if (p.name === 'on' && `@${arg}` === name) return exp
      if (`v-${p.name}` === name) return exp
      if (p.name === 'slot' && `#${arg}` === name) return exp
    }
  }
  return null
}

describe('Members, Invites and Files: one line a row on a phone (FR-120 P4b)', () => {
  const cases: [string, string][] = [
    ['src/components/admin/MembersSection.vue', 'member'],
    ['src/views/invite/InviteManageView.vue', 'invite'],
    ['src/views/files/FilesBrowser.vue', 'file'],
  ]
  for (const [path, noun] of cases) {
    it(`${noun}: an xs-only #item row whose head opens the rest`, () => {
      const els = all(templateOf(path))
      const phone = els.filter((e) => e.tag === 'template' && attr(e, 'v-if') === 'xs' && attr(e, '#item') !== null)
      expect(phone, `${path}: <template v-if="xs" #item>`).toHaveLength(1)
      const inside = all(phone[0])
      // One cell the width of the row: never Vuetify's mobile row, whose
      // cells are a label | value grid that squeezed the line into half.
      const tr = inside.find((e) => e.tag === 'tr')!
      expect(attr(tr, 'class')).toBe('v-data-table__tr')
      expect(attr(inside.find((e) => e.tag === 'td')!, 'class')).toBe('v-data-table__td stack-row')
      const toggle = inside.find((e) => e.tag === 'button' && attr(e, 'data-testid') === `${noun}-row-toggle`)
      expect(toggle, `${noun}-row-toggle`).toBeTruthy()
      expect(attr(toggle!, 'class')).toBe('stack-toggle')
      expect(attr(toggle!, 'aria-expanded')).toBe('isOpen(item.id)')
      expect(attr(toggle!, '@click')).toBe('toggle(item.id)')
      const details = inside.find((e) => attr(e, 'data-testid') === `${noun}-row-details`)
      expect(details && attr(details, 'v-if')).toBe('isOpen(item.id)')
    })
  }

  it('gives an invite and a file one action on the line, named for a screen reader', () => {
    for (const [path, label] of [
      ['src/views/invite/InviteManageView.vue', "$t('mh.phone.copyInviteFor', { who: item.target_email || $t('mh.invite.anyone') })"],
      ['src/views/files/FilesBrowser.vue', "$t('mh.phone.downloadFile', { name: item.filename })"],
    ] as const) {
      const phone = all(templateOf(path)).find((e) => e.tag === 'template' && attr(e, 'v-if') === 'xs')!
      const named = all(phone).filter((e) => e.tag === 'v-btn' && attr(e, 'aria-label') === label)
      expect(named, path).toHaveLength(1)
    }
  })

  it('spells out why the owner has no Remove, which a desktop keeps in a tooltip', () => {
    expect(read('src/components/admin/MembersSection.vue')).toMatch(/<span v-else[^>]*>\s*<v-icon[^>]*>mdi-crown<\/v-icon>\s*\{\{ \$t\('mh\.members\.ownerFixed'\) \}\}/)
  })
})

describe('the usage tables and the keep-busy history: a card per row on a phone', () => {
  it('stacks the Calls and Tunnel sessions tables, each value labelled', () => {
    const tables = all(templateOf('src/components/stats/UsagePanel.vue')).filter((e) => e.tag === 'v-table')
    expect(tables.map((t) => attr(t, 'class'))).toEqual(['table-stack-xs table-stack-xs--compact', 'table-stack-xs table-stack-xs--compact'])
    const labels = all(tables[1]).filter((e) => e.tag === 'td').map((td) => attr(td, 'data-label'))
    expect(labels).toEqual([null, 'Org', 'From', 'Until', 'Duration', 'Traffic'])
  })

  it('stacks the keep-busy history and explains its source chip on a tap', () => {
    const els = all(templateOf('src/components/admin/KeepBusyHistorySection.vue'))
    const table = els.find((e) => e.tag === 'v-table')!
    expect(attr(table, 'class')).toBe('table-stack-xs table-stack-xs--compact')
    expect(all(table).filter((e) => e.tag === 'td').every((td) => attr(td, 'data-label') !== null)).toBe(true)
    const chip = els.find((e) => e.tag === 'FactChip')
    expect(chip && attr(chip, 'explain')).toBe('sourceHint(e)')
    // No chip keeps its meaning in a title alone.
    expect(els.filter((e) => e.tag === 'v-chip' && attr(e, 'title') !== null)).toEqual([])
  })
})

describe('the agent log on a phone', () => {
  it('shows the phone slice of the filtered lines, 200 at a time, with a way to the older ones', () => {
    const src = read('src/components/admin/AgentLogsDialog.vue')
    expect(src).toContain('usePhoneSlice(filteredLines, LOG_PAGE)')
    expect(src).toContain('const LOG_PAGE = 200')
    const els = all(templateOf('src/components/admin/AgentLogsDialog.vue'))
    expect(els.some((e) => attr(e, 'v-for') === '(line, i) in shownLines')).toBe(true)
    const older = els.find((e) => attr(e, 'data-testid') === 'agent-logs-older')
    expect(older && attr(older, '@click')).toBe('showOlder')
  })
})

// --- the room search, mounted ---

beforeAll(() => {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
})

vi.mock('vue-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('vue-router')>()),
  useRoute: () => ({ params: { tenantId: 't1' } }),
  useRouter: () => ({ push: vi.fn() }),
}))
vi.mock('@/api/client', () => ({
  api: { get: vi.fn(async () => []), post: vi.fn(), put: vi.fn(), delete: vi.fn() },
  ApiError: class extends Error {},
}))

import RoomList from '@/views/rooms/RoomList.vue'
import { useRoomStore } from '@/stores/rooms'

describe('the room search (FR-120 P4b)', () => {
  const realWidth = window.innerWidth
  beforeEach(() => setActivePinia(createPinia()))
  afterEach(() => Object.defineProperty(window, 'innerWidth', { value: realWidth, configurable: true }))

  async function mountRooms() {
    Object.defineProperty(window, 'innerWidth', { value: 360, configurable: true })
    const store = useRoomStore()
    const w = mount(RoomList, {
      global: {
        plugins: [createVuetify({ components, directives })],
        mocks: { $t: (k: string) => k },
        stubs: { RoomTreeItem: { props: ['room'], template: '<div class="tree-item">{{ room.name }}</div>' }, RouterLink: true },
      },
    })
    await flushPromises()
    store.rooms = [
      { id: 'r1', name: 'Engineering' },
      { id: 'r2', name: 'Backend', parent_id: 'r1' },
      { id: 'r3', name: 'Incidents', parent_id: 'r2' },
      { id: 'r4', name: 'Marketing' },
    ] as never
    store.loading = false
    await flushPromises()
    return w
  }

  it('lists the rooms whose name matches, each with its path; an empty search gives the tree back', async () => {
    const w = await mountRooms()
    expect(w.findAll('.tree-item').map((t) => t.text())).toEqual(['Engineering', 'Marketing'])
    await w.get('[data-testid="room-search"] input').setValue('inc')
    const results = w.get('[data-testid="room-search-results"]')
    expect(results.findAll('.v-list-item-title').map((t) => t.text())).toEqual(['Incidents'])
    expect(results.get('.v-list-item-subtitle').text()).toBe('Engineering / Backend')
    expect(w.find('.tree-item').exists()).toBe(false)
    await w.get('[data-testid="room-search"] input').setValue('zzz')
    expect(w.get('[data-testid="room-search-results"]').text()).toContain('No room\'s name contains "zzz"')
    await w.get('[data-testid="room-search"] input').setValue('')
    expect(w.findAll('.tree-item')).toHaveLength(2)
  })
})
