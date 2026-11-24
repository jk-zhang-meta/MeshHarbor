// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-120 P4 — the Devices page on a phone is one line per device until a line
// is tapped (D2): the name, the OS, the status and one action (Connect for a
// device, the menu for a tunnel client). The open card is the FR-116 card,
// unchanged; a tablet and a desktop never see the closed line. Ten open cards
// were 3.7× the desktop grid at 360 px (FR-120 §2.1).
//
// AgentsSection is too large to mount for this, so its template is parsed and
// the card's structure is locked, as fr120P1Facts.spec.ts does; the open/closed
// state itself is `useOpenRows`, tested here directly. The field proof is the
// page's height on production (FR-120 §8).
import { describe, expect, it } from 'vitest'
import { computed } from 'vue'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parse as parseSfc } from '@vue/compiler-sfc'
import { NodeTypes, type ElementNode, type TemplateChildNode } from '@vue/compiler-dom'
import { useOpenRows } from '@/composables/useOpenRows'

describe('useOpenRows', () => {
  it('opens and closes each row on its own', () => {
    const { isOpen, toggle } = useOpenRows<string>()
    expect(isOpen('a')).toBe(false)
    toggle('a')
    expect(isOpen('a')).toBe(true)
    expect(isOpen('b')).toBe(false)
    toggle('b')
    toggle('a')
    expect(isOpen('a')).toBe(false)
    expect(isOpen('b')).toBe(true)
  })

  it('re-renders what reads it', () => {
    const { isOpen, toggle } = useOpenRows<string>()
    const label = computed(() => (isOpen('a') ? 'open' : 'closed'))
    expect(label.value).toBe('closed')
    toggle('a')
    expect(label.value).toBe('open')
  })
})

const source = readFileSync(resolve(process.cwd(), 'src/components/admin/AgentsSection.vue'), 'utf8')
const root = parseSfc(source, { filename: 'AgentsSection.vue' }).descriptor.template!.ast as unknown as ElementNode

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
    }
  }
  return null
}

const all: ElementNode[] = []
walk(root, (el) => all.push(el))
const card = all.find((el) => el.tag === 'v-card' && (attr(el, 'data-testid') ?? '').includes('device-card-'))!

describe('AgentsSection — a phone card is one line until tapped (FR-120 P4, D2)', () => {
  it('has the phone card', () => {
    expect(card).toBeTruthy()
  })

  it('makes the card head a button on a phone only, saying whether it is open', () => {
    const head = below(card, (e) => e.tag === 'component' && (attr(e, 'is') ?? '').includes("'button'"))
    expect(head).toHaveLength(1)
    expect(attr(head[0], 'is')).toBe("xs ? 'button' : 'div'")
    expect(attr(head[0], 'aria-expanded')).toBe('xs ? isCardOpen(item) : undefined')
    expect(attr(head[0], '@click')).toBe('xs && toggleCard(item)')
    // The name and the status stay on the closed line.
    expect(head[0].loc.source).toContain('deviceLabel(item)')
  })

  it('opens the chips, the access and details panels and the actions on a tap', () => {
    const gated = (e: ElementNode) => (attr(e, 'v-if') ?? '').includes('!xs || isCardOpen(item)')
    const chips = below(card, (e) => e.tag === 'div' && (attr(e, 'v-if') ?? '').includes('cardHasChips(item)'))
    expect(chips.length).toBe(1)
    expect(gated(chips[0])).toBe(true)
    for (const tag of ['v-expansion-panels', 'v-card-actions']) {
      const els = below(card, (e) => e.tag === tag)
      expect(els, tag).toHaveLength(1)
      expect(gated(els[0]), `${tag} opens on a tap`).toBe(true)
    }
  })

  it('offers one action on a closed line: Connect for a device, the menu for a tunnel client', () => {
    const closed = below(card, (e) => e.tag === 'template' && attr(e, 'v-if') === 'xs && !isCardOpen(item)')
    expect(closed).toHaveLength(1)
    const connect = below(closed[0], (e) => e.tag === 'v-btn')
    expect(connect).toHaveLength(1)
    expect(attr(connect[0], 'v-if')).toBe("item.kind === 'agent'")
    expect(attr(connect[0], 'aria-label')).toBe("$t('mh.dev.connectTo', { name: deviceLabel(item) })")
    expect(attr(connect[0], 'to')).toContain("name: 'agent-remote'")
    const menu = below(closed[0], (e) => e.tag === 'DeviceActionsMenu')
    expect(menu).toHaveLength(1)
    expect(menu[0].props.some((p) => p.type === NodeTypes.DIRECTIVE && p.name === 'else')).toBe(true)
  })

  it('keeps the OS on the closed line, named for a screen reader', () => {
    const os = below(card, (e) => e.tag === 'v-icon' && attr(e, 'v-if') === 'xs && !isCardOpen(item)')
    expect(os).toHaveLength(1)
    expect(attr(os[0], 'icon')).toBe('osIcon(item.os)')
    expect(attr(os[0], 'aria-label')).toBe('osName(item.os)')
  })
})
