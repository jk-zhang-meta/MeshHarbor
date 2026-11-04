// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-88 (#1790) §3b — the static pages' purestat goals that `docs.js` fires:
 * `install-copy` from an install/enroll command's copy button, and
 * `github-outbound` from a link to the repository. (`subscribe` is home.js's,
 * in home.spec.ts.)
 *
 * docs.js is RUN against a rendered page. The build decides which code blocks
 * are install commands (`isInstallCommand`, the `data-install` marker), so
 * that decision is tested here too, against the commands `enrollCommands.ts`
 * actually prints.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it, vi } from 'vitest'
import { enrollCommands } from '../../src/utils/enrollCommands.ts'
import { SITE_ORIGIN } from '../site.ts'
import { renderPage, type DocPage } from '../theme/layout.ts'
import { createRenderer, isInstallCommand, renderMarkdown } from '../theme/render.ts'
import type { SiteAssets } from '../theme/shell.ts'

const DOCS_JS = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'theme', 'docs.js'), 'utf8')

const assets: SiteAssets = {
  css: '/docs/assets/docs.0123456789.css',
  js: '/docs/assets/docs.abcdefabcd.js',
  search: '/docs/assets/search.1111111111.js',
  osPreference: '/docs/assets/os-preference.2222222222.js',
  searchIndex: '/docs/assets/search-index.3333333333.json',
}

const md = createRenderer()
const body = renderMarkdown(
  md,
  [
    ':::enroll',
    ':::',
    '',
    '```bash',
    'mh ssh my-laptop',
    '```',
    '',
    'Source: [the repository](https://github.com/jk-zhang-meta/MeshHarbor/blob/master/LICENSING.md),',
    '[the author](https://github.com/gjovanov), [another repo](https://github.com/jk-zhang-meta/meshharbor-docs),',
    '[the docs](/docs/faq/).',
  ].join('\n'),
  'test.md',
).html

const page: DocPage = {
  slug: 'start/quickstart',
  url: '/docs/start/quickstart/',
  outFile: 'start/quickstart/index.html',
  title: 'Quickstart',
  description: 'Enroll a machine.',
  tags: [],
  order: 1,
  noindex: false,
  html: body,
  headings: [],
  plain: '',
  faq: false,
  sourceFile: 'start/quickstart',
}

interface Run {
  doc: Document
  purestat: ReturnType<typeof vi.fn>
}

/** Run docs.js on the page. `withPurestat: false` is a visit where the
 *  analytics script is absent (blocked, or `ANALYTICS = null`). */
function run(withPurestat = true): Run {
  const doc = new DOMParser().parseFromString(renderPage({ nav: [], page, assets }, new Set()), 'text/html')
  // No navigation in a test document, whatever is clicked.
  doc.addEventListener('click', (e) => e.preventDefault(), true)
  const purestat = vi.fn()
  const win: Record<string, unknown> = { isSecureContext: true }
  if (withPurestat) win.purestat = purestat
  const nav = { clipboard: { writeText: vi.fn(() => Promise.resolve()) } }
  new Function('window', 'document', 'navigator', DOCS_JS)(win, doc, nav)
  return { doc, purestat }
}

const settle = () => new Promise((r) => setTimeout(r, 0))
const click = (el: Element, init: MouseEventInit = {}) =>
  el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, ...init }))

describe('isInstallCommand — what counts as an install/enroll command', () => {
  it('recognises every command enrollCommands prints, for both kinds and every scope', () => {
    for (const kind of ['agent', 'tunnel'] as const) {
      for (const scope of ['system', 'machine', 'user'] as const) {
        for (const os of enrollCommands(kind, SITE_ORIGIN, null, scope)) {
          for (const b of os.blocks.filter((x) => !x.isDownload)) {
            expect(isInstallCommand(b.command), b.command).toBe(true)
          }
        }
      }
    }
  })

  it('recognises the install guides’ hand-written one-liners', () => {
    expect(isInstallCommand('curl -fsSL https://meshharbor.itachi.fans/api/setup/install.sh | sh -s -- \\\n  --role daemon --token <t>')).toBe(true)
    expect(isInstallCommand('& ([scriptblock]::Create((irm https://meshharbor.itachi.fans/api/setup/install.ps1))) -Role daemon-system')).toBe(true)
    expect(isInstallCommand('meshharbord enroll --server https://meshharbor.itachi.fans --token <reusable-key> --ephemeral --name ci-runner')).toBe(true)
  })

  it('does not count commands that USE MeshHarbor, or anything else', () => {
    for (const cmd of [
      'mh ssh <device-name>',
      'mh forward --agent <device-name> --local 127.0.0.1:5432 --remote db:5432',
      'git clone https://github.com/jk-zhang-meta/MeshHarbor.git',
      'docker compose up -d',
      'echo enroll --server',
      'meshharbord --version',
    ]) {
      expect(isInstallCommand(cmd), cmd).toBe(false)
    }
  })

  it('marks the rendered install blocks, and only those', () => {
    const doc = new DOMParser().parseFromString(body, 'text/html')
    const blocks = [...doc.querySelectorAll('[data-code]')]
    const marked = blocks.filter((b) => b.hasAttribute('data-install'))
    expect(marked.length).toBeGreaterThanOrEqual(3)
    for (const b of marked) expect(isInstallCommand(b.querySelector('code')!.textContent!)).toBe(true)
    const plain = blocks.find((b) => b.textContent!.includes('mh ssh'))!
    expect(plain.hasAttribute('data-install')).toBe(false)
  })
})

describe('docs.js — install-copy', () => {
  it('fires once when an install command’s copy button copies', async () => {
    const { doc, purestat } = run()
    click(doc.querySelector('[data-install] .code-copy')!)
    await settle()
    expect(purestat).toHaveBeenCalledTimes(1)
    expect(purestat).toHaveBeenCalledWith('install-copy')
  })

  it('does not fire for any other code block', async () => {
    const { doc, purestat } = run()
    const plain = [...doc.querySelectorAll('[data-code]')].find((b) => !b.hasAttribute('data-install'))!
    click(plain.querySelector('.code-copy')!)
    await settle()
    expect(purestat).not.toHaveBeenCalled()
    // The copy itself still happened.
    expect(plain.querySelector('.code-copy')!.classList.contains('is-copied')).toBe(true)
  })

  it('is a no-op, and the copy still works, without purestat', async () => {
    const { doc } = run(false)
    const btn = doc.querySelector('[data-install] .code-copy')!
    expect(() => click(btn)).not.toThrow()
    await settle()
    expect(btn.classList.contains('is-copied')).toBe(true)
  })
})

describe('docs.js — github-outbound', () => {
  const link = (doc: Document, href: string) => doc.querySelector(`a[href="${href}"]`)!

  it('fires for every link into the repository: the top bar, the prose, "Edit this page"', () => {
    const { doc, purestat } = run()
    click(link(doc, 'https://github.com/jk-zhang-meta/MeshHarbor'))
    click(link(doc, 'https://github.com/jk-zhang-meta/MeshHarbor/blob/master/LICENSING.md'))
    click(link(doc, 'https://github.com/jk-zhang-meta/MeshHarbor/edit/master/ui/docs/content/start/quickstart.md'))
    expect(purestat.mock.calls).toEqual([['github-outbound'], ['github-outbound'], ['github-outbound']])
  })

  it('does not fire for the author’s profile, another repository, or an internal link', () => {
    const { doc, purestat } = run()
    click(link(doc, 'https://github.com/gjovanov'))
    click(link(doc, 'https://github.com/jk-zhang-meta/meshharbor-docs'))
    click(link(doc, '/docs/faq/'))
    expect(purestat).not.toHaveBeenCalled()
  })

  it('counts a middle click (a new tab has no click event), and nothing else', () => {
    const { doc, purestat } = run()
    const a = link(doc, 'https://github.com/jk-zhang-meta/MeshHarbor')
    a.dispatchEvent(new MouseEvent('auxclick', { bubbles: true, button: 1 }))
    a.dispatchEvent(new MouseEvent('auxclick', { bubbles: true, button: 2 }))
    expect(purestat.mock.calls).toEqual([['github-outbound']])
  })

  it('is a no-op without purestat', () => {
    const { doc } = run(false)
    expect(() => click(link(doc, 'https://github.com/jk-zhang-meta/MeshHarbor'))).not.toThrow()
  })
})
