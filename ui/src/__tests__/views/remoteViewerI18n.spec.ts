// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-131 AC4 — no remote-viewer string is English-only in the Chinese UI.
//
// The viewer's templates hold no prose of their own: every word a person
// reads goes through vue-i18n, so it has a Chinese reading. Each template is
// parsed and its text and the attributes a person reads (title, label,
// aria-label, …) are checked for words; a bound attribute is an expression
// and is fine. What is allowed to stay as written is listed: key legends and
// technical names, which read the same in both languages.
//
// And every key the viewer reads has Chinese in its Chinese reading, except
// the technical names listed.
import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { parse as parseSfc } from '@vue/compiler-sfc'
import { NodeTypes, type ElementNode, type TemplateChildNode } from '@vue/compiler-dom'
import zhCN from '@/locales/zh-CN.json'

const VIEWER_FILES = [
  'src/views/remote/RemoteControl.vue',
  ...readdirSync(resolve(process.cwd(), 'src/components/remote'))
    .filter((f) => f.endsWith('.vue'))
    .map((f) => join('src/components/remote', f)),
]

/** Attributes whose static value a person reads. */
const READ_ATTRS = new Set(['title', 'label', 'aria-label', 'placeholder', 'hint', 'messages', 'subtitle', 'close-label', 'text', 'alt'])

/** Text that reads the same in both languages: key legends, protocol and tool
 *  names, single letters. */
const AS_WRITTEN = new Set(['REC', 'tmux:', 'L', 'R', 'S', 'M', 'Esc', 'Tab', 'Ctrl', 'Alt', 'Win', 'Home', 'End', 'Del'])

function words(text: string): string | null {
  const t = text.replace(/\s+/g, ' ').trim()
  if (!t || AS_WRITTEN.has(t)) return null
  if (/^mdi-[a-z0-9-]+$/.test(t)) return null // an icon name, not text
  return /[A-Za-z]{2,}/.test(t) ? t : null
}

function englishIn(file: string): string[] {
  const source = readFileSync(resolve(process.cwd(), file), 'utf8')
  const { descriptor } = parseSfc(source, { filename: file })
  const found: string[] = []
  const walk = (node: ElementNode | TemplateChildNode) => {
    if (node.type === NodeTypes.TEXT) {
      const w = words(node.content)
      if (w) found.push(`${file}:${node.loc.start.line} text "${w}"`)
      return
    }
    if (node.type !== NodeTypes.ELEMENT) {
      if ('children' in node && Array.isArray(node.children)) {
        for (const c of node.children as TemplateChildNode[]) walk(c)
      }
      return
    }
    for (const p of node.props) {
      if (p.type === NodeTypes.ATTRIBUTE && READ_ATTRS.has(p.name) && p.value) {
        const w = words(p.value.content)
        if (w) found.push(`${file}:${p.loc.start.line} ${p.name}="${w}"`)
      }
    }
    for (const c of node.children as TemplateChildNode[]) walk(c)
  }
  walk(descriptor.template!.ast as unknown as ElementNode)
  return found
}

type Tree = { [k: string]: string | Tree }
function leaves(tree: Tree, prefix = ''): [string, string][] {
  return Object.entries(tree).flatMap(([k, v]) =>
    typeof v === 'string' ? [[prefix + k, v] as [string, string]] : leaves(v, `${prefix}${k}.`),
  )
}

/** Keys whose Chinese reading is the technical name itself. */
const TECHNICAL = new Set([
  'remote.codec.codecs.av1',
  'remote.codec.codecs.hevc',
  'remote.codec.codecs.vp9',
  'remote.codec.codecs.h264',
  'remote.viewer.rec.ofSize',
  'remote.viewer.feature.sep',
])

describe('FR-131 AC4 — the remote viewer in Chinese', () => {
  it.each(VIEWER_FILES)('%s has no English-only words in its template', (file) => {
    expect(englishIn(file)).toEqual([])
  })

  it('every viewer key reads in Chinese, technical names aside', () => {
    const zh = leaves(zhCN as unknown as Tree).filter(
      ([k]) => k.startsWith('remote.') || k.startsWith('keepBusy.'),
    )
    expect(zh.length).toBeGreaterThan(400)
    const untranslated = zh.filter(([k, v]) => !TECHNICAL.has(k) && !/[一-鿿]/.test(v)).map(([k]) => k)
    expect(untranslated).toEqual([])
  })

  it('catches what it is for: an English word left in a template', () => {
    // A positive control, so the scan above cannot pass by finding nothing.
    expect(words('Start recording')).toBe('Start recording')
    expect(words('mdi-record')).toBeNull()
    expect(words('REC')).toBeNull()
  })
})
