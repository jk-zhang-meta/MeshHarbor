// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-120 P1 — on the Devices page no chip's meaning is hover-only. A `v-chip`
// that carries a `title` must also do something on a tap (Device
// configuration's opens the dialog that explains it); every other explained
// chip is a FactChip, which opens its explanation on a tap. And the phone
// card's presence dot, which only repeats the status chip beside it, carries
// no title of its own.
//
// AgentsSection is too large to mount for this, so its template is parsed and
// the rule is checked over every chip, as rcRatingMount.spec.ts does.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parse as parseSfc } from '@vue/compiler-sfc'
import { NodeTypes, type ElementNode, type TemplateChildNode } from '@vue/compiler-dom'

const source = readFileSync(resolve(process.cwd(), 'src/components/admin/AgentsSection.vue'), 'utf8')
const { descriptor } = parseSfc(source, { filename: 'AgentsSection.vue' })
const root = descriptor.template!.ast as unknown as ElementNode

function walk(node: ElementNode | TemplateChildNode, visit: (el: ElementNode) => void): void {
  if (!('children' in node) || !Array.isArray(node.children)) return
  if (node.type === NodeTypes.ELEMENT) visit(node)
  for (const c of node.children as TemplateChildNode[]) walk(c, visit)
}

/** True when the element has the attribute, static or bound. */
function has(el: ElementNode, name: string): boolean {
  return el.props.some(
    (p) =>
      (p.type === NodeTypes.ATTRIBUTE && p.name === name) ||
      (p.type === NodeTypes.DIRECTIVE && p.name === 'bind' && !!p.arg && 'content' in p.arg && p.arg.content === name),
  )
}
const onClick = (el: ElementNode) =>
  el.props.some((p) => p.type === NodeTypes.DIRECTIVE && p.name === 'on' && !!p.arg && 'content' in p.arg && p.arg.content === 'click')

const all: ElementNode[] = []
walk(root, (el) => all.push(el))

describe('AgentsSection — no chip is hover-only (FR-120 P1)', () => {
  it('gives every titled v-chip a tap of its own', () => {
    const titled = all.filter((el) => el.tag === 'v-chip' && has(el, 'title'))
    const hoverOnly = titled.filter((el) => !onClick(el))
    expect(hoverOnly.map((el) => el.loc.source.split('\n').slice(0, 3).join(' ').trim())).toEqual([])
  })

  it('explains the needs-a-person chips with FactChip, in the grid and on the card', () => {
    const facts = all.filter((el) => el.tag === 'FactChip')
    expect(facts.every((el) => has(el, 'explain'))).toBe(true)
    // Status, credential, stall and key rotation (grid and card), ephemeral
    // (both), the permission warnings (both), the companion and keep busy (card).
    expect(facts.length).toBeGreaterThanOrEqual(14)
  })

  it("explains the card's presence word on a tap and leaves its dot without a title", () => {
    const card = all.find((el) => el.tag === 'v-card' && has(el, 'data-testid') && el.loc.source.includes('device-card-'))
    expect(card, 'the phone card').toBeTruthy()
    const presence: ElementNode[] = []
    const dots: ElementNode[] = []
    walk(card!, (el) => {
      if (el.tag === 'FactChip' && el.loc.source.includes('rowPresenceTitle(item)')) presence.push(el)
      if (el.tag === 'span' && el.loc.source.startsWith('<span class="mh-presence__dot"')) dots.push(el)
    })
    expect(presence).toHaveLength(1)
    expect(has(presence[0], 'explain')).toBe(true)
    expect(has(presence[0], 'title')).toBe(false)
    expect(dots).toHaveLength(1)
    expect(has(dots[0], 'title')).toBe(false)
    expect(has(dots[0], 'aria-hidden')).toBe(true)
  })
})
