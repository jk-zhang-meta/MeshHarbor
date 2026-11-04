// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-60 (#1165) — markdown -> HTML.
 *
 * Built on `markdown-it@14`, which is ALREADY a `ui` dependency (the chat
 * composer uses it), so the renderer costs no new package.
 *
 * ⚠️ DOMPurify is deliberately NOT used here even though it is also a
 * dependency. It is a DOM sanitiser for UNTRUSTED input; this content is
 * first-party Markdown committed to this repo and reviewed in PRs, and
 * running it would drag `jsdom` into the build for no boundary that
 * actually exists. The XSS boundary in this product is chat message HTML
 * (`ui/src/composables/useMarkdown.ts`) — that one keeps its allowlist.
 *
 * Block extensions, all implemented as a line-oriented PRE-PASS rather
 * than markdown-it plugins, because `markdown-it-container` is not a
 * dependency and the whole grammar here is four fence shapes:
 *
 *   :::note | :::tip | :::warning | :::danger  [optional title]
 *   :::os        with `@windows` / `@macos` / `@linux` section markers
 *   :::enroll    expands from ui/src/utils/enrollCommands.ts (never hand-written)
 *   :::cards     a markdown list -> the landing page's feature-card grid
 *   :::badges    a markdown list -> the tutorial's badge row
 *   :::steps     a markdown ordered list -> the tutorial's numbered steps
 *   :::video <id>  a click-to-load YouTube facade (FR-88 P3); the body, if
 *                  any, is its caption. The id must be in ui/src/utils/videos.ts
 */
import MarkdownIt from 'markdown-it'
import type { Token } from 'markdown-it/index.js'
import { icon, OS_ICON, OS_LABEL } from './icons.ts'
import { enrollCommands, type EnrollOs } from '../../src/utils/enrollCommands.ts'
import { videoById, type SiteVideo } from '../../src/utils/videos.ts'
import { videoFacade } from './video.ts'
import { SITE_ORIGIN } from '../site.ts'

export interface Heading {
  level: number
  text: string
  slug: string
}

/** A video the page embeds, with its published poster (null when the
 *  renderer has no image hook, as in most unit tests). */
export interface PageVideo {
  video: SiteVideo
  poster: ResolvedImage | null
}

export interface RenderResult {
  html: string
  headings: Heading[]
  /** Every `:::video` on the page, in order: the layout's structured data. */
  videos: PageVideo[]
}

/** What an image resolves to once the build has published it. */
export interface ResolvedImage {
  url: string
  width: number
  height: number
}

/**
 * The markdown-it `env` for one file. The build supplies the hooks; the unit
 * tests mostly do not, and then a gate THROWS instead of collecting.
 */
export interface RenderEnv {
  filePath: string
  /** Publishes a markdown image `src` and returns its URL and intrinsic size,
   *  or null when it has already reported why it cannot. */
  resolveImage?: (src: string) => ResolvedImage | null
  /** Collects a build error, so one run reports every problem in a file. */
  fail?: (msg: string) => void
}

function report(env: RenderEnv, msg: string): void {
  const full = `${env.filePath} — ${msg}`
  if (env.fail) env.fail(full)
  else throw new Error(full)
}

const CALLOUTS = {
  note: { icon: 'info', label: 'Note' },
  tip: { icon: 'tip', label: 'Tip' },
  warning: { icon: 'warning', label: 'Warning' },
  danger: { icon: 'danger', label: 'Careful' },
} as const

const OS_ORDER: EnrollOs[] = ['windows', 'macos', 'linux']

/**
 * Heading slugs are URLs, so this mapping is a compatibility surface and
 * is locked by `__tests__/render.spec.ts`.
 *
 * ⚠️ Everything that is not a letter or a number becomes a separator.
 * The first version kept `À-ÿ` to preserve accented Latin letters, but
 * that range also contains punctuation — so `Consent — and audit` slugged
 * to `consent-—-and-audit` and shipped a percent-encoded em dash inside
 * every deep link to it. `\p{L}` keeps the accented letters without the
 * punctuation, which is what was actually wanted.
 */
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/`/g, '')
    .replace(/[^\p{L}\p{N}]+/gu, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^-|-$/g, '')
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/** Wraps content so markdown-it renders the INNER markdown: an HTML block
 *  ends at a blank line, so the blank lines here are load-bearing, not
 *  formatting. Without them the whole container is swallowed as raw HTML
 *  and the prose inside never renders. */
function htmlBlock(open: string, inner: string, close: string): string {
  return `${open}\n\n${inner.trim()}\n\n${close}`
}

// ── the enroll directive ────────────────────────────────────────────────
// The commands come from the SAME vitest-locked module the landing page and
// the in-app enrollment dialog use, so a flag or binary rename fails
// `enrollCommands.spec.ts` instead of silently shipping stale docs.
function renderEnroll(kind: 'agent' | 'tunnel', groupId: string): string {
  const matrix = enrollCommands(kind, SITE_ORIGIN, null)
  const panels: string[] = []
  const tabs: string[] = []
  const radios: string[] = []

  for (const [i, os] of OS_ORDER.entries()) {
    const entry = matrix.find((m) => m.os === os)
    if (!entry) continue
    const id = `${groupId}-${os}`
    radios.push(
      `<input type="radio" name="${groupId}" id="${id}" class="os-radio os-radio--${os}"${i === 0 ? ' checked' : ''}>`,
    )
    tabs.push(
      `<label for="${id}" class="os-tab" data-os="${os}">${icon(OS_ICON[os]!, { size: 17 })}<span>${OS_LABEL[os]}</span></label>`,
    )
    const blocks = entry.blocks
      .map((b) => {
        if (b.isDownload) {
          return (
            `<p class="os-block-label">${escapeHtml(b.label)}</p>` +
            `<p><a class="btn btn--tonal" href="${escapeHtml(b.command)}">${icon('download', { size: 17 })}<span>Download</span></a></p>`
          )
        }
        return (
          `<p class="os-block-label">${escapeHtml(b.label)}</p>` +
          codeBlock(b.command, os === 'windows' ? 'powershell' : 'bash')
        )
      })
      .join('\n')
    const note = entry.note
      ? `<p class="os-note">${icon('info', { size: 16 })}<span>${escapeHtml(entry.note)}</span></p>`
      : ''
    panels.push(`<div class="os-panel os-panel--${os}">${blocks}${note}</div>`)
  }

  return (
    `<div class="os-tabs" data-os-tabs role="group" aria-label="Choose an operating system">${radios.join('')}` +
    `<div class="os-tablist">${tabs.join('')}</div>` +
    `<div class="os-panels">${panels.join('')}</div></div>`
  )
}

/**
 * FR-88 (#1790) §3b: an agent install or enroll command — the one-line
 * installers, or `meshharbord`/`meshharbor … enroll … --server`. Its copy button
 * counts toward purestat's `install-copy` goal (`docs.js` reads the
 * `data-install` this puts on the block). Decided from the command itself, so
 * the `:::enroll` blocks and the install guides' hand-written fences count
 * alike.
 */
export function isInstallCommand(code: string): boolean {
  return (
    /\/api\/setup\/install\.(?:sh|ps1)\b/.test(code) ||
    /\bmeshharbord?\b[^\n]*\benroll\b[^\n]*--server\b/.test(code)
  )
}

/**
 * A code block with its own header row.
 *
 * ⚠️ The language label and the copy button are in a HEADER, not absolutely
 * positioned over the code. They were overlaid at first, and every install
 * command — the longest lines on the site, and the ones people copy — ran
 * underneath the label. An overlay only looks fine on short samples.
 */
function codeBlock(code: string, lang: string): string {
  const label = lang ? escapeHtml(lang) : ''
  return (
    `<div class="code-block" data-code${isInstallCommand(code) ? ' data-install' : ''}>` +
    `<div class="code-head"><span class="code-lang">${label}</span>` +
    `<button class="code-copy" type="button" aria-label="Copy code to clipboard">${icon('copy', { size: 15 })}</button></div>` +
    `<pre><code class="language-${escapeHtml(lang)}">${escapeHtml(code)}</code></pre></div>`
  )
}

// ── the pre-pass ────────────────────────────────────────────────────────

interface PrePassCtx {
  md: MarkdownIt
  filePath: string
  groupSeq: { n: number }
  env: RenderEnv
  videos: PageVideo[]
}

/** An opening code fence: three or more backticks or tildes. */
const FENCE_OPEN = /^ {0,3}(`{3,}|~{3,})/
const FENCE_CLOSE = /^ {0,3}(`{3,}|~{3,})\s*$/
const ATX_HEADING = /^ {0,3}(#{1,6})(?:\s|$)/

/**
 * Tracks whether a line is inside a fenced code block, so the pre-pass never
 * reads a line of CODE as markup: a `# comment` in a bash sample is not a
 * heading, and a `:::note` in a sample showing the syntax is not a container.
 */
function fenceTracker(): (line: string) => boolean {
  let open: string | null = null
  return (line) => {
    if (open) {
      const close = FENCE_CLOSE.exec(line)
      if (close && close[1]![0] === open[0] && close[1]!.length >= open.length) open = null
      return true
    }
    const start = FENCE_OPEN.exec(line)
    if (start) {
      open = start[1]!
      return true
    }
    return false
  }
}

function parseListItems(body: string): string[] {
  const items: string[] = []
  let current: string | null = null
  for (const raw of body.split('\n')) {
    const m = /^\s*(?:[-*]|\d+\.)\s+(.*)$/.exec(raw)
    if (m) {
      if (current !== null) items.push(current)
      current = m[1]!
    } else if (current !== null && raw.trim() !== '') {
      current += ' ' + raw.trim()
    }
  }
  if (current !== null) items.push(current)
  return items
}

/** `**Title** — rest` / `**Title** - rest` / `**Title**: rest` -> [title, rest]. */
function splitLeadIn(item: string): { title: string; rest: string } {
  const m = /^\*\*(.+?)\*\*\s*(?:[—–-]|:)?\s*([\s\S]*)$/.exec(item)
  if (!m) return { title: '', rest: item }
  return { title: m[1]!, rest: m[2]!.trim() }
}

/**
 * @param level the heading level for each card's title: one below the
 *   heading the grid sits under, so a grid under `## Read on` titles its
 *   cards `<h3>` and one directly under the page's `<h1>` titles them `<h2>`.
 *   (FR-60 opened `<h2>` and closed `</h3>`, which a browser repairs to
 *   `<h2>` — the wrong level under every `##`.)
 */
function renderCards(ctx: PrePassCtx, body: string, level: number): string {
  const h = `h${level}`
  const cards = parseListItems(body).map((item) => {
    const { title, rest } = splitLeadIn(item)
    // `icon:name` anywhere in the item picks the glyph and is removed from the copy.
    const iconMatch = /\bicon:([a-zA-Z]+)\b/.exec(rest)
    const glyph = iconMatch ? iconMatch[1]! : 'chevronRight'
    const text = rest.replace(/\s*\bicon:[a-zA-Z]+\b\s*/, ' ').trim()
    return (
      `<div class="card"><span class="card__icon">${icon(glyph, { size: 22 })}</span>` +
      `<${h} class="card__title">${ctx.md.renderInline(title, ctx.env)}</${h}>` +
      `<p class="card__text">${ctx.md.renderInline(text, ctx.env)}</p></div>`
    )
  })
  return `<div class="card-grid">${cards.join('')}</div>`
}

function renderBadges(ctx: PrePassCtx, body: string): string {
  const badges = parseListItems(body).map((item) => {
    const { title, rest } = splitLeadIn(item)
    const iconMatch = /\bicon:([a-zA-Z]+)\b/.exec(rest)
    const glyph = iconMatch ? iconMatch[1]! : 'check'
    const text = rest.replace(/\s*\bicon:[a-zA-Z]+\b\s*/, ' ').trim()
    return (
      `<div class="badge-card"><span class="badge-card__icon">${icon(glyph, { size: 20 })}</span>` +
      `<div><span class="badge-card__title">${ctx.md.renderInline(title, ctx.env)}</span> ` +
      `<span class="badge-card__text">${ctx.md.renderInline(text, ctx.env)}</span></div></div>`
    )
  })
  return `<div class="badge-row">${badges.join('')}</div>`
}

function renderOsTabs(ctx: PrePassCtx, body: string, groupId: string, level: number): string {
  const sections = new Map<string, string[]>()
  let current: string | null = null
  for (const line of body.split('\n')) {
    const m = /^@(windows|macos|linux)\s*$/.exec(line.trim())
    if (m) {
      current = m[1]!
      sections.set(current, [])
      continue
    }
    if (current) sections.get(current)!.push(line)
  }
  if (sections.size === 0) {
    throw new Error(
      `${ctx.filePath} — \`:::os\` block has no \`@windows\` / \`@macos\` / \`@linux\` markers`,
    )
  }

  const radios: string[] = []
  const tabs: string[] = []
  const panels: string[] = []
  let first = true
  for (const os of OS_ORDER) {
    const lines = sections.get(os)
    if (!lines) continue
    const id = `${groupId}-${os}`
    radios.push(
      `<input type="radio" name="${groupId}" id="${id}" class="os-radio os-radio--${os}"${first ? ' checked' : ''}>`,
    )
    tabs.push(
      `<label for="${id}" class="os-tab" data-os="${os}">${icon(OS_ICON[os]!, { size: 17 })}<span>${OS_LABEL[os]}</span></label>`,
    )
    panels.push(
      `<div class="os-panel os-panel--${os}">${ctx.md.render(prePass(ctx, lines.join('\n'), level), ctx.env)}</div>`,
    )
    first = false
  }

  return (
    `<div class="os-tabs" data-os-tabs role="group" aria-label="Choose an operating system">${radios.join('')}` +
    `<div class="os-tablist">${tabs.join('')}</div>` +
    `<div class="os-panels">${panels.join('')}</div></div>`
  )
}

/**
 * Rewrites `:::` containers into HTML blocks, innermost content left as
 * markdown so markdown-it still renders it.
 *
 * NESTING IS SUPPORTED and matters: a per-OS block almost always wants a
 * `:::warning` inside one of its tabs (the macOS permission traps are the
 * motivating case). Depth is tracked so the matching `:::` closes the
 * right container, and every container body is recursively pre-passed —
 * otherwise an inner container would be embedded inside an HTML block and
 * markdown-it would render its `:::` markers as literal text.
 *
 * An unclosed container is an ERROR: one that silently ran to end of file
 * would swallow the rest of the page into a callout.
 *
 * Code fences are skipped (FR-87): a line inside one is code, never a
 * container marker or a heading.
 *
 * @param level the heading level in force where `src` begins; `#` lines move
 *   it, and a `:::cards` grid titles its cards one level below it.
 */
function prePass(ctx: PrePassCtx, src: string, level = 1): string {
  const lines = src.split('\n')
  const out: string[] = []
  const inCode = fenceTracker()

  for (let i = 0; i < lines.length; i++) {
    if (inCode(lines[i]!)) {
      out.push(lines[i]!)
      continue
    }
    const heading = ATX_HEADING.exec(lines[i]!)
    if (heading) level = heading[1]!.length
    const open = /^:::\s*([a-z]+)\s*(.*)$/.exec(lines[i]!.trimEnd())
    if (!open) {
      out.push(lines[i]!)
      continue
    }
    const kind = open[1]!
    const arg = open[2]!.trim()

    // Collect to the *matching* closing `:::`, counting nested opens.
    const bodyLines: string[] = []
    const bodyInCode = fenceTracker()
    let depth = 1
    let closed = false
    let j = i + 1
    for (; j < lines.length; j++) {
      const line = lines[j]!.trimEnd()
      if (bodyInCode(lines[j]!)) {
        bodyLines.push(lines[j]!)
        continue
      }
      if (/^:::\s*$/.test(line)) {
        depth -= 1
        if (depth === 0) {
          closed = true
          break
        }
      } else if (/^:::\s*[a-z]+/.test(line)) {
        depth += 1
      }
      bodyLines.push(lines[j]!)
    }
    if (!closed) {
      throw new Error(`${ctx.filePath}:${i + 1} — \`:::${kind}\` block is never closed with \`:::\``)
    }
    const body = bodyLines.join('\n')
    i = j

    if (kind in CALLOUTS) {
      const c = CALLOUTS[kind as keyof typeof CALLOUTS]
      const title = arg || c.label
      out.push(
        htmlBlock(
          `<div class="callout callout--${kind}"><p class="callout__head">${icon(c.icon, { size: 18 })}<span>${escapeHtml(title)}</span></p><div class="callout__body">`,
          prePass(ctx, body, level),
          `</div></div>`,
        ),
      )
      continue
    }

    switch (kind) {
      case 'os':
        ctx.groupSeq.n += 1
        out.push(renderOsTabs(ctx, body, `os-${ctx.groupSeq.n}`, level))
        break
      case 'enroll': {
        ctx.groupSeq.n += 1
        const kindArg = arg === 'tunnel' ? 'tunnel' : 'agent'
        out.push(renderEnroll(kindArg, `os-${ctx.groupSeq.n}`))
        break
      }
      case 'cards':
        out.push(renderCards(ctx, body, Math.min(6, level + 1)))
        break
      case 'badges':
        out.push(renderBadges(ctx, body))
        break
      case 'steps':
        out.push(htmlBlock('<div class="doc-steps">', prePass(ctx, body, level), '</div>'))
        break
      case 'video': {
        // A build gate (FR-60's rule): an id the manifest does not hold fails
        // the build, so a typo never ships a player of somebody else's video.
        const video = videoById(arg)
        if (!video) {
          report(ctx.env, `\`:::video ${arg}\` is not in ui/src/utils/videos.ts. Add the video there first (a public one only).`)
          break
        }
        const poster = ctx.env.resolveImage ? ctx.env.resolveImage(video.poster) : null
        ctx.videos.push({ video, poster })
        const caption = body.trim() ? ctx.md.renderInline(body.trim()) : undefined
        out.push('', videoFacade(video, poster, caption), '')
        break
      }
      default:
        throw new Error(
          `${ctx.filePath} — unknown container \`:::${kind}\`. ` +
            `Known: note, tip, warning, danger, os, enroll, cards, badges, steps, video.`,
        )
    }
  }

  return out.join('\n')
}

// ── markdown-it instance ────────────────────────────────────────────────

export function createRenderer(): MarkdownIt {
  const md = new MarkdownIt({
    html: true,
    linkify: true,
    typographer: true,
    breaks: false,
  })

  // Fenced code -> the copy-button block.
  md.renderer.rules.fence = (tokens, idx) => {
    const t = tokens[idx]!
    return codeBlock(t.content.replace(/\n$/, ''), (t.info || '').trim().split(/\s+/)[0] ?? '')
  }

  // Tables scroll inside their own container; the page body must never
  // scroll horizontally on a phone.
  md.renderer.rules.table_open = () => '<div class="table-wrap"><table>'
  md.renderer.rules.table_close = () => '</table></div>'

  // External links open in a new tab and say so.
  const defaultLinkOpen =
    md.renderer.rules.link_open ??
    ((tokens, idx, options, _env, self) => self.renderToken(tokens, idx, options))
  md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
    const href = tokens[idx]!.attrGet('href') ?? ''
    if (/^https?:\/\//i.test(href) && !href.startsWith(SITE_ORIGIN)) {
      tokens[idx]!.attrSet('target', '_blank')
      tokens[idx]!.attrSet('rel', 'noopener noreferrer')
      tokens[idx]!.attrJoin('class', 'link-external')
    }
    return defaultLinkOpen(tokens, idx, options, env, self)
  }

  // ── images (FR-87) ────────────────────────────────────────────────────
  // `![alt](name.png "caption")`. The build publishes the file under a
  // content-hashed name and supplies its real size, so the browser reserves
  // the right box before the bytes arrive.
  md.renderer.rules.image = (tokens, idx, options, env: RenderEnv, self) => {
    const tok = tokens[idx]!
    const src = tok.attrGet('src') ?? ''
    const alt = self.renderInlineAsText(tok.children ?? [], options, env).trim()
    const caption = tok.attrGet('title') ?? ''

    if (!alt) {
      report(env, `image "${src}" has no alt text. Say what it shows: alt text is what a screen reader reads out and what image search indexes.`)
    }
    let resolved: ResolvedImage | null = null
    if (/^([a-z][a-z0-9+.-]*:|\/\/)/i.test(src)) {
      report(env, `image "${src}" is not a local file. Put it in the collection's assets directory: a remote image is a third-party request on every view, and it can change or vanish.`)
    } else if (env.resolveImage) {
      resolved = env.resolveImage(src)
    }

    const size = resolved ? ` width="${resolved.width}" height="${resolved.height}"` : ''
    const img = `<img src="${escapeHtml(resolved?.url ?? src)}" alt="${escapeHtml(alt)}"${size} loading="lazy" decoding="async">`
    return tok.meta?.figure && caption ? `${img}<figcaption>${md.renderInline(caption, env)}</figcaption>` : img
  }

  // An image alone in its paragraph is a figure, and its markdown title is
  // the caption. An image inside a sentence stays inline.
  md.core.ruler.push('figure', (state) => {
    const t = state.tokens
    for (let i = 0; i + 2 < t.length; i++) {
      const open = t[i]!
      const inline = t[i + 1]!
      if (open.type !== 'paragraph_open' || open.hidden || inline.type !== 'inline' || t[i + 2]!.type !== 'paragraph_close') {
        continue
      }
      const kids = (inline.children ?? []).filter(
        (c) => c.type !== 'softbreak' && !(c.type === 'text' && c.content.trim() === ''),
      )
      if (kids.length !== 1 || kids[0]!.type !== 'image') continue
      kids[0]!.meta = { ...(kids[0]!.meta ?? {}), figure: true }
      open.tag = 'figure'
      open.attrJoin('class', 'figure')
      t[i + 2]!.tag = 'figure'
    }
  })

  return md
}

/**
 * A raw `<img>` bypasses the image rule: no size, no lazy loading, no hashed
 * name, and nothing checks its alt text.
 *
 * ⚠️ Checked on the AUTHORED source, never the pre-passed one. After the
 * pre-pass every container is raw HTML — an OS tab holding a perfectly good
 * markdown image included — so a check there would refuse legal content.
 * Parsing (not rendering) the source sees raw HTML as html tokens, and code
 * as code, so a sample showing an `<img>` tag is left alone.
 */
function checkRawImages(md: MarkdownIt, source: string, env: RenderEnv): void {
  for (const tok of md.parse(source, {})) {
    const html = [tok, ...(tok.children ?? [])].filter((x) => x.type === 'html_block' || x.type === 'html_inline')
    if (html.some((x) => /<img\b/i.test(x.content))) {
      report(env, 'a raw <img> tag. Use markdown, ![alt text](file.png "optional caption"), so the image gets its size, lazy loading and a cache-safe name.')
      return
    }
  }
}

/** Heading ids + permalinks, collected for the on-page TOC and the search
 *  index in one pass so the two can never disagree about what a page contains. */
function anchorHeadings(tokens: Token[]): Heading[] {
  const headings: Heading[] = []
  const seen = new Map<string, number>()

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]!
    if (tok.type !== 'heading_open') continue
    const inline = tokens[i + 1]
    if (!inline || inline.type !== 'inline') continue

    const level = Number(tok.tag.slice(1))
    const text = inline.content.replace(/`/g, '').trim()
    let slug = slugify(text)
    if (slug === '') slug = `section-${headings.length + 1}`
    const dup = seen.get(slug) ?? 0
    seen.set(slug, dup + 1)
    if (dup > 0) slug = `${slug}-${dup + 1}`

    tok.attrSet('id', slug)
    headings.push({ level, text, slug })

    // h2/h3 get a hover permalink. h1 is the page title and needs none.
    if (level >= 2 && level <= 3) {
      const link = new (inline.constructor as new (t: string, g: string, n: number) => Token)(
        'html_inline',
        '',
        0,
      )
      link.content = `<a class="heading-anchor" href="#${slug}" aria-label="Link to this section">${icon('link', { size: 15 })}</a>`
      inline.children = [...(inline.children ?? []), link]
    }
  }

  return headings
}

export function renderMarkdown(
  md: MarkdownIt,
  source: string,
  filePath: string,
  hooks: Omit<RenderEnv, 'filePath'> = {},
): RenderResult {
  const env: RenderEnv = { filePath, ...hooks }
  checkRawImages(md, source, env)
  const ctx: PrePassCtx = { md, filePath, groupSeq: { n: 0 }, env, videos: [] }
  const expanded = prePass(ctx, source)
  const tokens = md.parse(expanded, env)
  const headings = anchorHeadings(tokens)
  return { html: md.renderer.render(tokens, md.options, env), headings, videos: ctx.videos }
}

export { escapeHtml }
