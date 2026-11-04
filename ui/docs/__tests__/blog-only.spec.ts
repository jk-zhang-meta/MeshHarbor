// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-91 (#1880) — `bun docs/build.ts --blog-only`: the blog's own publishing
 * lane. These run the REAL generator, twice into temp directories, because the
 * claims are about what it writes:
 *
 *   - AC1: for the published post, the blog-only tree is the full build's
 *     `/blog/**` with `/docs/assets/` replaced by `/blog/assets/` — the same
 *     pages, the same feed and urlset, the same asset bytes;
 *   - the lane depends on nothing under the image's `/docs/assets/`, whose
 *     hashed names change with every image the lane does not follow;
 *   - AC7: a post that shows an install command fails without `installCopy:
 *     true` and builds with it, and the carry script then knows its URL;
 *   - the flag-less build uses none of the lane's machinery.
 */
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const HERE = dirname(fileURLToPath(import.meta.url))
const UI = join(HERE, '..', '..')

function build(args: string[]): { code: number | null; log: string } {
  const r = spawnSync('bun', ['docs/build.ts', ...args], { cwd: UI, encoding: 'utf8' })
  return { code: r.status, log: `${r.stdout ?? ''}${r.stderr ?? ''}${r.error ? String(r.error) : ''}` }
}

function files(dir: string): string[] {
  const out: string[] = []
  const walk = (d: string) => {
    for (const e of readdirSync(d)) {
      const p = join(d, e)
      if (statSync(p).isDirectory()) walk(p)
      else out.push(relative(dir, p).split('\\').join('/'))
    }
  }
  walk(dir)
  return out.sort()
}

const tmp = mkdtempSync(join(tmpdir(), 'fr91-'))
const FULL = join(tmp, 'full')
const LANE = join(tmp, 'lane')

afterAll(() => rmSync(tmp, { recursive: true, force: true }))

describe('--blog-only, the published post (AC1)', () => {
  beforeAll(() => {
    const full = build(['--out', FULL])
    expect(full.code, full.log).toBe(0)
    const lane = build(['--blog-only', '--out', LANE])
    expect(lane.code, lane.log).toBe(0)
  })

  it('writes the blog and its urlset, and nothing else', () => {
    expect(readdirSync(LANE).sort()).toEqual(['blog', 'sitemap-blog.xml'])
    expect(files(join(LANE, 'blog'))).toContain('404.html')
    expect(files(join(LANE, 'blog'))).toContain('feed.xml')
  })

  it('every page, the feed and the urlset equal the full build once asset URLs are normalised', () => {
    const lanePages = files(join(LANE, 'blog')).filter((f) => !f.startsWith('assets/') && f !== '404.html')
    expect(lanePages.sort()).toEqual(files(join(FULL, 'blog')).sort())
    for (const f of lanePages) {
      const lane = readFileSync(join(LANE, 'blog', f), 'utf8').replaceAll('/blog/assets/', '/docs/assets/')
      expect(lane, f).toBe(readFileSync(join(FULL, 'blog', f), 'utf8'))
    }
    expect(readFileSync(join(LANE, 'sitemap-blog.xml'), 'utf8')).toBe(readFileSync(join(FULL, 'sitemap-blog.xml'), 'utf8'))
  })

  it('its 404 is the docs 404 on the lane’s own assets', () => {
    const lane = readFileSync(join(LANE, 'blog', '404.html'), 'utf8').replaceAll('/blog/assets/', '/docs/assets/')
    expect(lane).toBe(readFileSync(join(FULL, 'docs', '404.html'), 'utf8'))
  })

  it('loads nothing from /docs/assets/, and every asset it names is in its own tree, byte for byte the image’s', () => {
    const html = files(LANE).filter((f) => /\.(html|xml)$/.test(f))
    const named = new Set<string>()
    for (const f of html) {
      const text = readFileSync(join(LANE, f), 'utf8')
      expect(text.includes('/docs/assets/'), `${f} names /docs/assets/`).toBe(false)
      // `&` ends a name too: the feed carries its HTML escaped (`…svg&quot;`). So does `?`: a
      // `?v=` busts a cache and names the same file (the social card's, docs/public-site.md §3).
      for (const m of text.matchAll(/\/blog\/assets\/([^"'\s)<&?]+)/g)) named.add(m[1]!)
    }
    expect(named.size).toBeGreaterThanOrEqual(5)
    for (const name of named) {
      const own = join(LANE, 'blog', 'assets', name)
      expect(existsSync(own), `blog/assets/${name}`).toBe(true)
      expect(readFileSync(own).equals(readFileSync(join(FULL, 'docs', 'assets', name))), name).toBe(true)
    }
  })

  it('the full build (no flag) uses none of the lane: no /blog/assets/, posts on /docs/assets/', () => {
    expect(existsSync(join(FULL, 'blog', 'assets'))).toBe(false)
    expect(existsSync(join(FULL, 'blog', '404.html'))).toBe(false)
    for (const f of files(FULL).filter((x) => x.endsWith('.html'))) {
      expect(readFileSync(join(FULL, f), 'utf8').includes('/blog/assets/'), f).toBe(false)
    }
    expect(readFileSync(join(FULL, 'blog', 'index.html'), 'utf8')).toContain('/docs/assets/')
  })
})

describe('installCopy (AC7)', () => {
  const FIXTURE = join(tmp, 'fixture-blog')
  const post = (installCopy: boolean) =>
    [
      '---',
      'title: Install the MeshHarbor agent on a Linux server in one line',
      'description: A fixture for FR-91: this post shows the install command, so it has to declare itself an install page.',
      'date: 2026-10-01T10:00:00Z',
      'author: goran',
      'tags: [install, linux]',
      'ogImage: social-preview.png',
      'ogImageAlt: The MeshHarbor social card',
      ...(installCopy ? ['installCopy: true'] : []),
      '---',
      '',
      'Run this on the server:',
      '',
      '```bash',
      'curl -fsSL https://meshharbor.itachi.fans/api/setup/install.sh | sh',
      '```',
      '',
    ].join('\n')

  function laneWith(installCopy: boolean) {
    rmSync(FIXTURE, { recursive: true, force: true })
    mkdirSync(join(FIXTURE, 'posts'), { recursive: true })
    writeFileSync(join(FIXTURE, 'posts', 'install-check.md'), post(installCopy))
    const out = join(tmp, installCopy ? 'ac7-with' : 'ac7-without')
    return { out, ...build(['--blog-only', '--blog-dir', FIXTURE, '--out', out]) }
  }

  it('a post that shows an install command fails without `installCopy: true`', () => {
    const r = laneWith(false)
    expect(r.code).toBe(1)
    expect(r.log).toMatch(/\/blog\/install-check\/ is not in INSTALL_PAGES/)
  })

  it('builds with it, and the carry script then names the post as an install page', () => {
    const r = laneWith(true)
    expect(r.code, r.log).toBe(0)
    const carry = readdirSync(join(r.out, 'blog', 'assets')).find((f) => /^attribution\.[0-9a-f]{10}\.js$/.test(f))
    expect(carry).toBeDefined()
    expect(readFileSync(join(r.out, 'blog', 'assets', carry!), 'utf8')).toContain('"/blog/install-check/"')
  })
})
