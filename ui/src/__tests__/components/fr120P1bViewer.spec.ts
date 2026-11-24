// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-120 P1b — in the remote viewer, a greyed control says why where a finger
// can read it. A disabled v-btn takes no pointer events, so its `title`
// reached no one — and the viewer is used on phones and tablets.
//   - The Settings panel: every disabled toggle is followed by a caption that
//     reads the same reason its title holds.
//   - The toolbar: refused clipboard, Record and Privacy controls sit in a
//     span that takes the tap and says why (`explainRefusal`).
//   - Touch mode: a tap says how the new mode works.
//   - A failed transfer shows its error as text; the files drawer's icon
//     buttons are named.
//
// RemoteControl.vue is too large to mount for these, so its template is parsed
// and each site is checked, as rcRatingMount.spec.ts does.
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { parse as parseSfc } from '@vue/compiler-sfc'
import { NodeTypes, type ElementNode, type TemplateChildNode } from '@vue/compiler-dom'

const source = readFileSync(resolve(process.cwd(), 'src/views/remote/RemoteControl.vue'), 'utf8')
const { descriptor } = parseSfc(source, { filename: 'RemoteControl.vue' })
const root = descriptor.template!.ast as unknown as ElementNode
const script = descriptor.scriptSetup?.content ?? ''

function walk(node: ElementNode | TemplateChildNode, visit: (el: ElementNode, parent: ElementNode | null) => void, parent: ElementNode | null = null): void {
  if (!('children' in node) || !Array.isArray(node.children)) return
  const el = node.type === NodeTypes.ELEMENT ? (node as ElementNode) : null
  if (el) visit(el, parent)
  for (const c of node.children as TemplateChildNode[]) walk(c, visit, el ?? parent)
}

const all: { el: ElementNode; parent: ElementNode | null }[] = []
walk(root, (el, parent) => all.push({ el, parent }))

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
function directive(el: ElementNode, name: string, arg?: string): string | null {
  for (const p of el.props) {
    if (p.type !== NodeTypes.DIRECTIVE || p.name !== name) continue
    if (arg !== undefined && !(p.arg && 'content' in p.arg && p.arg.content === arg)) continue
    return p.exp && 'content' in p.exp ? p.exp.content.trim() : ''
  }
  return null
}
const byTestId = (id: string) => {
  const found = all.filter(({ el }) => attr(el, 'data-testid') === id)
  expect(found, `one element with data-testid="${id}"`).toHaveLength(1)
  return found[0]
}
/** The element after `el` among its parent's element children. */
function nextElement(el: ElementNode, parent: ElementNode): ElementNode | undefined {
  const kids = parent.children.filter((c): c is ElementNode => c.type === NodeTypes.ELEMENT)
  return kids[kids.indexOf(el) + 1]
}
/** The text a caption interpolates (`{{ x }}` → `x`). */
function interpolated(el: ElementNode): string {
  const i = el.children.find((c) => c.type === NodeTypes.INTERPOLATION)
  return i && i.type === NodeTypes.INTERPOLATION && 'content' in i.content ? i.content.content.trim() : ''
}

describe('the viewer Settings panel: a disabled toggle says why, as text (FR-120 P1b)', () => {
  // [the toggle (found by its label's i18n key, FR-131 P3), its caption's test id, the caption's v-if, what it reads]
  const cases: [string, string, string, string][] = [
    ['remote.viewer.settings.matchDisplay', 'rc-display-match-why', '!agentSupportsDisplayMatch', 'displayMatchTooltip'],
    ['remote.viewer.session.audio', 'rc-audio-why', 'sessionLive || !agentSupportsAudio', 'audioTooltip'],
    ['remote.viewer.session.relay', 'rc-local-relay-why', 'sessionLive', 'localRelayTooltip'],
    ['remote.viewer.session.clipSync', 'rc-clipboard-autosync-why', 'rc.clipboardGranted.value && clipboardRefusal', 'clipboardRefusal'],
  ]
  it.each(cases)('%s', (label, captionId, shownWhen, reads) => {
    const btn = all.find(({ el }) => el.tag === 'v-btn' && el.loc.source.includes(`t('${label}'`))
    expect(btn, `the "${label}" toggle`).toBeTruthy()
    const caption = byTestId(captionId)
    // Right after its toggle, in the same parent.
    expect(nextElement(btn!.el, btn!.parent!)).toBe(caption.el)
    expect(directive(caption.el, 'if')).toBe(shownWhen)
    expect(interpolated(caption.el)).toBe(reads)
  })

  it('says why Upload and Browse are greyed, under them', () => {
    const browse = byTestId('rc-files-browse')
    const caption = byTestId('rc-files-why')
    expect(nextElement(browse.el, browse.parent!)).toBe(caption.el)
    expect(directive(caption.el, 'if')).toBe('filesWhy')
    expect(interpolated(caption.el)).toBe('filesWhy')
    // The session's refusal speaks first, then Browse's own reason.
    expect(script).toMatch(/const filesWhy = computed<string \| null>\(\(\) => \{\s*if \(filesRefusal\.value\) return filesRefusal\.value/)
  })
})

describe('the viewer toolbar: a refused control says why on a tap (FR-120 P1b)', () => {
  const tapSays = (wrapId: string, btnId: string | null) => {
    const wrap = byTestId(wrapId)
    expect(wrap.el.tag).toBe('span')
    expect(directive(wrap.el, 'on', 'click')).toMatch(/explainRefusal\(/)
    if (btnId) expect(byTestId(btnId).parent).toBe(wrap.el)
  }

  it('the clipboard buttons', () => {
    tapSays('rc-clipboard-send-wrap', 'rc-clipboard-send')
    tapSays('rc-clipboard-get-wrap', 'rc-clipboard-get')
  })

  it('Record and Privacy, refused', () => {
    tapSays('rc-record-refused', null)
    tapSays('rc-privacy-refused', null)
  })

  it('Privacy, not ready yet', () => {
    tapSays('rc-privacy-wrap', 'rc-privacy-btn')
    // The v-if moved to the span, so the refused span still continues its chain.
    expect(directive(byTestId('rc-privacy-wrap').el, 'if')).toBe('rc.phase.value === \'connected\' && rc.privacyGranted.value')
    expect(directive(byTestId('rc-privacy-btn').el, 'if')).toBeNull()
  })

  it('the reason shows in the snackbar', () => {
    expect(script).toMatch(/function explainRefusal\(why: string \| null \| undefined\): void \{\s*if \(why\) showSnackbar\(why, 'info', 6000\)/)
  })
})

describe('touch mode, a failed transfer, the files drawer (FR-120 P1b)', () => {
  it('a tap on the touch-mode control says how the new mode works', () => {
    expect(directive(byTestId('rc-touch-mode').el, 'on', 'click')).toBe('toggleTouchMode')
    expect(script).toMatch(/const TOUCH_MODE_HELP = \{\s*trackpad: '[^']+',\s*direct: '[^']+',\s*\} as const/)
    expect(script).toMatch(/rc\.setTouchMode\(next\)\s*showSnackbar\(t\(TOUCH_MODE_HELP\[next\]\)/)
  })

  it('a failed transfer shows its error as text', () => {
    const err = byTestId('rc-transfer-error')
    expect(directive(err.el, 'if')).toBe("xfer.status === 'error' && xfer.error")
    expect(interpolated(err.el)).toBe('xfer.error')
  })

  it("names every icon button in the files drawer's toolbar and path row", () => {
    const drawer = all.find(({ el }) => el.tag === 'v-navigation-drawer' && attr(el, 'class')?.includes('files-drawer'))
    expect(drawer, 'the files drawer').toBeTruthy()
    const buttons: ElementNode[] = []
    walk(drawer!.el, (el) => {
      if (el.tag === 'v-btn' && attr(el, 'icon') !== null && attr(el, 'title') !== null) buttons.push(el)
    })
    expect(buttons.length).toBeGreaterThanOrEqual(5)
    const unnamed = buttons.filter((b) => !attr(b, 'aria-label')).map((b) => attr(b, 'title'))
    expect(unnamed).toEqual([])
  })
})
