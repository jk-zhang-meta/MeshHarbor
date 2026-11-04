// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-60 (#1165) — the renderer's contract.
 *
 * The load-bearing cases are the ones that fail SILENTLY if they regress:
 * a container that swallows the rest of the page, a nested callout that
 * renders its own `:::` markers as literal text, and — most importantly —
 * the install commands drifting away from the module that owns them.
 */
import { describe, expect, it } from 'vitest'
import { createRenderer, renderMarkdown, slugify } from '../theme/render.ts'
import { enrollCommands } from '../../src/utils/enrollCommands.ts'
import { SITE_ORIGIN } from '../site.ts'

const md = createRenderer()
const render = (src: string) => renderMarkdown(md, src, 'test.md').html

describe('containers', () => {
  it('renders each callout kind with its own class', () => {
    for (const kind of ['note', 'tip', 'warning', 'danger']) {
      const html = render(`:::${kind}\nBody text.\n:::`)
      expect(html).toContain(`callout--${kind}`)
      expect(html).toContain('Body text.')
    }
  })

  it('renders the container body as MARKDOWN, not as literal text', () => {
    // The blank lines the generator inserts around an HTML block are what
    // make this work. Without them markdown-it swallows the whole
    // container as raw HTML and the prose inside never renders.
    const html = render(':::note\nSome **bold** text.\n:::')
    expect(html).toContain('<strong>bold</strong>')
  })

  it('uses an explicit title when one is given', () => {
    expect(render(':::warning Read this first\nBody.\n:::')).toContain('Read this first')
  })

  it('supports NESTING — a callout inside an OS tab', () => {
    // The motivating case: every per-OS page wants a warning inside one of
    // its tabs. Before depth tracking, the `:::os` closed on the warning's
    // `:::` and the rest of the page landed outside the tab group.
    const html = render(
      [':::os', '@windows', 'Windows body.', ':::warning Careful', 'Nested body.', ':::', ':::'].join(
        '\n',
      ),
    )
    expect(html).toContain('os-panel--windows')
    expect(html).toContain('callout--warning')
    expect(html).toContain('Nested body.')
    // No stray marker leaked through as text.
    expect(html).not.toMatch(/(^|[^:]):::($|[^:])/)
  })

  it('throws on an unclosed container rather than swallowing the page', () => {
    expect(() => render(':::note\nBody with no terminator.')).toThrow(/never closed/)
  })

  it('throws on an unknown container rather than dropping it silently', () => {
    expect(() => render(':::nonsense\nBody.\n:::')).toThrow(/unknown container/)
  })
})

describe('OS tabs', () => {
  const html = render(
    [':::os', '@windows', 'W body', '@macos', 'M body', '@linux', 'L body', ':::'].join('\n'),
  )

  it('emits one radio, one label and one panel per OS', () => {
    for (const os of ['windows', 'macos', 'linux']) {
      expect(html).toContain(`os-radio--${os}`)
      expect(html).toContain(`data-os="${os}"`)
      expect(html).toContain(`os-panel--${os}`)
    }
  })

  it('pre-checks the first OS so the block works with JavaScript disabled', () => {
    // The CSS-only mechanism is the baseline; docs.js only persists a
    // choice. A block with nothing checked would render empty without JS.
    expect(html).toMatch(/os-radio--windows"\s+checked/)
  })

  it('throws when no OS markers are present', () => {
    expect(() => render(':::os\nno markers here\n:::')).toThrow(/@windows/)
  })

  it('gives each block on a page its own radio group', () => {
    const two = render(
      [
        ':::os',
        '@windows',
        'one',
        ':::',
        '',
        ':::os',
        '@windows',
        'two',
        ':::',
      ].join('\n'),
    )
    const groups = [...two.matchAll(/name="(os-\d+)"/g)].map((m) => m[1])
    expect(new Set(groups).size).toBe(2)
  })
})

describe('the enroll directive is generated, never hand-written', () => {
  // THE anti-drift lock. If a flag, binary name or install role is renamed
  // in enrollCommands.ts, this fails here instead of shipping stale docs.
  const html = render(':::enroll\n:::')
  const matrix = enrollCommands('agent', SITE_ORIGIN, null)

  it('renders every shell command from enrollCommands verbatim', () => {
    for (const os of matrix) {
      for (const block of os.blocks) {
        if (block.isDownload) continue
        // The generator HTML-escapes, so compare against the escaped form.
        const escaped = block.command
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
        expect(html).toContain(escaped)
      }
    }
  })

  it('renders download blocks as links rather than as shell commands', () => {
    const download = matrix.flatMap((o) => o.blocks).find((b) => b.isDownload)
    expect(download).toBeDefined()
    expect(html).toContain(`href="${download!.command}"`)
  })

  it('carries each platform note through', () => {
    for (const os of matrix) {
      if (!os.note) continue
      expect(html).toContain(os.note.replace(/'/g, '&#39;').slice(0, 30))
    }
  })
})

describe('code blocks', () => {
  it('puts the language label in a header, not over the code', () => {
    // An overlaid label ran underneath every long install command — the
    // exact lines people copy. The header row is the fix.
    const html = render('```bash\necho hello\n```')
    expect(html).toContain('code-head')
    expect(html).toContain('>bash<')
    expect(html).toContain('code-copy')
    expect(html.indexOf('code-head')).toBeLessThan(html.indexOf('<pre>'))
  })

  it('escapes the code rather than interpreting it', () => {
    expect(render('```html\n<script>x</script>\n```')).toContain('&lt;script&gt;')
  })
})

describe('headings', () => {
  it('assigns stable ids and a permalink to h2 and h3', () => {
    const { html, headings } = renderMarkdown(md, '## Exit nodes\n\n### DNS\n', 'test.md')
    expect(headings.map((h) => h.slug)).toEqual(['exit-nodes', 'dns'])
    expect(html).toContain('id="exit-nodes"')
    expect(html).toContain('heading-anchor')
  })

  it('disambiguates duplicate headings instead of colliding', () => {
    const { headings } = renderMarkdown(md, '## Setup\n\n## Setup\n', 'test.md')
    expect(headings.map((h) => h.slug)).toEqual(['setup', 'setup-2'])
  })
})

describe('slugify', () => {
  // Heading slugs are URLs. Changing how they are produced silently breaks
  // every inbound deep link, so the mapping is locked.
  it.each([
    ['Exit nodes', 'exit-nodes'],
    ['What the server sees', 'what-the-server-sees'],
    ['`mh status`', 'meshharbor-status'],
    ['Consent — and audit', 'consent-and-audit'],
    ['Ports & firewall', 'ports-firewall'],
    ['  Trailing  ', 'trailing'],
  ])('slugify(%j) === %j', (input, expected) => {
    expect(slugify(input)).toBe(expected)
  })
})

describe('external links', () => {
  it('opens off-site links in a new tab with rel=noopener', () => {
    const html = render('[GitHub](https://github.com/jk-zhang-meta/MeshHarbor)')
    expect(html).toContain('target="_blank"')
    expect(html).toContain('rel="noopener noreferrer"')
  })

  it('leaves internal links alone', () => {
    expect(render('[Quickstart](/docs/start/quickstart/)')).not.toContain('target="_blank"')
  })
})

describe('tables', () => {
  it('wraps a table so it scrolls inside its own container', () => {
    // The page body must never scroll horizontally on a phone.
    const html = render('| a | b |\n|---|---|\n| 1 | 2 |')
    expect(html).toContain('table-wrap')
  })
})

// ── FR-87 (#1776) ─────────────────────────────────────────────────────────

describe('card headings follow the outline', () => {
  const cards = ':::cards\n- **One** — first\n- **Two** — second\n:::'

  it('titles cards h2 directly under the page title, h3 under a section', () => {
    expect(render(cards)).toContain('<h2 class="card__title">One</h2>')
    expect(render(`## Read on\n\n${cards}`)).toContain('<h3 class="card__title">One</h3>')
  })

  it('always closes the tag it opened (FR-60 opened <h2> and closed </h3>)', () => {
    const html = render(`## Read on\n\n${cards}`)
    for (const [, open, close] of html.matchAll(/<(h\d) class="card__title">[^]*?<\/(h\d)>/g)) {
      expect(close).toBe(open)
    }
  })

  it('does not read a `# comment` inside a code fence as a heading', () => {
    const src = ['## Install', '', '```bash', '# not a heading', '```', '', cards].join('\n')
    expect(render(src)).toContain('<h3 class="card__title">One</h3>')
  })
})

describe('code fences are code, never markup', () => {
  it('renders a container marker inside a fence as text, not as a callout', () => {
    const html = render('```md\n:::note\nshown, not run\n:::\n```')
    expect(html).not.toContain('callout--note')
    expect(html).toContain(':::note')
  })

  it('does not let a fenced `:::` close the container around it', () => {
    const html = render([':::warning', '```text', ':::', '```', 'still inside', ':::'].join('\n'))
    expect(html).toMatch(/callout--warning[^]*still inside[^]*<\/div><\/div>/)
  })
})

describe('images', () => {
  const resolveImage = (src: string) => ({ url: `/docs/assets/${src.replace('.', '.0123456789.')}`, width: 1400, height: 788 })

  it('publishes a markdown image with its real size, lazily', () => {
    const { html } = renderMarkdown(md, 'Before ![A mesh of machines](mesh.png) after.', 'test.md', { resolveImage })
    expect(html).toContain('<img src="/docs/assets/mesh.0123456789.png" alt="A mesh of machines" width="1400" height="788" loading="lazy" decoding="async">')
    // Inside a sentence it stays inline.
    expect(html).not.toContain('<figure')
  })

  it('makes an image alone in its paragraph a figure, captioned by its title', () => {
    const { html } = renderMarkdown(md, '![A mesh](mesh.png "The mesh, *after* the upgrade")', 'test.md', { resolveImage })
    expect(html).toMatch(/^<figure class="figure"><img [^>]+><figcaption>The mesh, <em>after<\/em> the upgrade<\/figcaption><\/figure>/)
  })

  it('refuses an image with no alt text', () => {
    expect(() => render('![](mesh.png)')).toThrow(/no alt text/)
  })

  it('refuses a remote or inline-data image', () => {
    expect(() => render('![x](https://example.com/x.png)')).toThrow(/not a local file/)
    expect(() => render('![x](//example.com/x.png)')).toThrow(/not a local file/)
    expect(() => render('![x](data:image/png;base64,AAAA)')).toThrow(/not a local file/)
  })

  it('collects every problem in a file when the build supplies `fail`', () => {
    const errors: string[] = []
    renderMarkdown(md, '![](a.png)\n\n![b](https://x.y/b.png)', 'post.md', { fail: (m) => errors.push(m) })
    expect(errors).toHaveLength(2)
    expect(errors[0]).toMatch(/^post\.md — /)
  })

  it('refuses a raw <img> tag, block or inline', () => {
    expect(() => render('<img src="x.png" alt="x">')).toThrow(/raw <img>/)
    expect(() => render('Text <img src="x.png" alt="x"> text.')).toThrow(/raw <img>/)
  })

  it('leaves an <img> shown as code alone', () => {
    expect(() => render('Write `<img>` tags? No.\n\n```html\n<img src="x.png">\n```')).not.toThrow()
  })

  it('accepts a markdown image inside an OS tab, which the pre-pass turns into raw HTML', () => {
    // The raw-<img> check reads the AUTHORED source for this reason: after
    // the pre-pass, the whole tab group is an HTML block.
    const src = [':::os', '@windows', '![The Windows installer](setup.png)', ':::'].join('\n')
    const { html } = renderMarkdown(md, src, 'test.md', { resolveImage })
    expect(html).toContain('src="/docs/assets/setup.0123456789.png"')
  })
})
