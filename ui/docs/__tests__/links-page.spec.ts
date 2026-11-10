// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-88 (#1790) P2 — the link hub (`/links/`) and the short paths that
 * redirect to it.
 *
 * The page is rendered and its links read. The carry script is RUN against
 * it, as `attribution.spec.ts` runs it against the other page kinds, because
 * the one thing the hub is for is getting a profile visitor's campaign onto
 * sign-up and install. The nginx locations and `CHANNELS` are held together
 * both ways here. So is the rule that no SPA route shares a short path: nginx
 * matches an exact location first, and it would take over that route
 * without a word.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  CHANNELS,
  INSTALL_PAGES,
  MAX_DESCRIPTION_CHARS,
  MAX_TITLE_CHARS,
  ORG,
  REPO_URL,
  shortPathLocation,
} from '../site.ts'
import { carryScript } from '../theme/carry.ts'
import { LINKS_DESCRIPTION, LINKS_TITLE, LINKS_URL, renderLinks } from '../theme/links-layout.ts'
import type { ShellNav, SiteAssets } from '../theme/shell.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const UI = join(HERE, '..', '..')
const NGINX = readFileSync(join(UI, '..', 'files', 'nginx-pod.conf'), 'utf8')
const ROUTER = readFileSync(join(UI, 'src', 'plugins', 'router.ts'), 'utf8')
const SCRIPT = carryScript(readFileSync(join(HERE, '..', 'theme', 'attribution.js'), 'utf8'), INSTALL_PAGES)

const assets: SiteAssets = {
  css: '/docs/assets/docs.0123456789.css',
  js: '/docs/assets/docs.abcdefabcd.js',
  search: '/docs/assets/search.1111111111.js',
  osPreference: '/docs/assets/os-preference.2222222222.js',
  searchIndex: '/docs/assets/search-index.3333333333.json',
  blogCss: '/docs/assets/blog.4444444444.css',
  homeCss: '/docs/assets/home.5555555555.css',
  homeJs: '/docs/assets/home.6666666666.js',
  attribution: '/docs/assets/attribution.7777777777.js',
}
const nav: ShellNav = { current: 'links', hasBlog: true }
const html = (n: ShellNav = nav) => renderLinks({ assets, nav: n })
const parse = (h: string) => new DOMParser().parseFromString(h, 'text/html')
const hrefs = (doc: Document) => [...doc.querySelectorAll('a[href]')].map((a) => a.getAttribute('href')!)

/** `location = /x { return 302 <target>; }`, as path → target. */
function shortPathLocations(conf: string): Map<string, string> {
  const out = new Map<string, string>()
  for (const m of conf.matchAll(/location\s*=\s*(\/\S*)\s*\{\s*return\s+302\s+(\S+?);\s*\}/g)) out.set(m[1]!, m[2]!)
  return out
}

describe('the link hub page', () => {
  it('has a title and a description that fit, one canonical, and asks not to be ranked', () => {
    expect(LINKS_TITLE.length).toBeLessThanOrEqual(MAX_TITLE_CHARS)
    expect(LINKS_DESCRIPTION.length).toBeLessThanOrEqual(MAX_DESCRIPTION_CHARS)
    const doc = parse(html())
    expect(doc.title).toBe(LINKS_TITLE)
    expect(doc.querySelector('link[rel="canonical"]')?.getAttribute('href')).toBe(`https://meshharbor.itachi.fans${LINKS_URL}`)
    // It repeats the homepage for people who arrive from a profile; its links stay followed.
    expect(doc.querySelector('meta[name="robots"]')?.getAttribute('content')).toBe('noindex, follow')
    expect(doc.querySelectorAll('h1')).toHaveLength(1)
  })

  it('offers sign-up, an install page, the docs, the blog and the repository', () => {
    const links = hrefs(parse(html()))
    expect(links).toContain('/register')
    expect(links).toContain('/docs/start/quickstart/')
    expect(links).toContain('/docs/')
    expect(links).toContain('/blog/')
    expect(links).toContain(REPO_URL)
    // The install link is one the carry script reaches.
    expect(INSTALL_PAGES).toContain('/docs/start/quickstart/')
  })

  it('leaves the blog out when there is none, as every other page does', () => {
    const doc = parse(html({ current: 'links', hasBlog: false }))
    expect(hrefs(doc)).not.toContain('/blog/')
    // The brand goes to `/`, so the top bar keeps its Docs link.
    expect(doc.querySelector('.topbar__links a[href="/docs/"]')).not.toBeNull()
  })

  it('lists every channel profile, marked as ours', () => {
    const doc = parse(html())
    for (const c of CHANNELS) {
      const a = doc.querySelector(`a[href="${c.url}"]`)
      expect(a, `${c.name} is not linked`).not.toBeNull()
      expect(a!.getAttribute('rel')!.split(/\s+/)).toEqual(expect.arrayContaining(['me', 'noopener']))
      expect(a!.textContent).toContain(c.handle)
    }
  })

  it('names the same profiles in its structured data, and so does every page', () => {
    const graph = JSON.parse(parse(html()).querySelector('script[type="application/ld+json"]')!.textContent!)
    const org = graph['@graph'].find((n: { '@type': string }) => n['@type'] === 'Organization')
    expect(org.sameAs).toEqual([REPO_URL, ...CHANNELS.map((c) => c.url)])
    expect(ORG.sameAs).toEqual(org.sameAs)
  })

  it('has the homepage’s plain brand, and no in-page anchor it cannot resolve', () => {
    const doc = parse(html())
    expect(doc.querySelector('.brand')?.getAttribute('href')).toBe('/')
    const ids = new Set([...doc.querySelectorAll('[id]')].map((e) => e.id))
    for (const h of hrefs(doc).filter((x) => x.startsWith('#'))) expect(ids.has(h.slice(1)), h).toBe(true)
  })
})

describe('a profile visitor’s campaign, carried from the hub', () => {
  function run(href: string): Document {
    const doc = parse(html())
    Object.defineProperty(doc, 'referrer', { value: 'https://www.tiktok.com/' })
    new Function('window', 'document', SCRIPT)({ location: { href } }, doc)
    return doc
  }

  it('reaches sign-up and the install pages with the campaign the short path set', () => {
    const tt = CHANNELS.find((c) => c.id === 'tiktok')!
    const doc = run(`https://meshharbor.itachi.fans${shortPathLocation(tt)}`)
    const register = new URL(doc.querySelector('.links-actions a.btn--primary')!.getAttribute('href')!, 'https://meshharbor.itachi.fans')
    expect(register.pathname).toBe('/register')
    expect(Object.fromEntries(register.searchParams)).toEqual({
      utm_source: 'tiktok',
      utm_medium: 'bio',
      utm_campaign: 'profile',
      referrer_host: 'www.tiktok.com',
      landing_path: '/links/',
    })
    for (const path of ['/docs/start/quickstart/', '/docs/']) {
      const a = [...doc.querySelectorAll('a[href]')].find((e) => e.getAttribute('href')!.startsWith(`${path}?`))
      expect(a, `${path} did not carry the campaign`).toBeDefined()
    }
  })

  it('changes nothing without a campaign', () => {
    expect(hrefs(run('https://meshharbor.itachi.fans/links/'))).toEqual(hrefs(parse(html())))
  })
})

describe('the short paths (files/nginx-pod.conf)', () => {
  const locations = shortPathLocations(NGINX)

  it('redirect each channel’s path to the hub with that channel as the source', () => {
    for (const c of CHANNELS) {
      expect(locations.get(c.short), `${c.short} in nginx-pod.conf`).toBe(shortPathLocation(c))
      expect(new URL(shortPathLocation(c), 'https://meshharbor.itachi.fans').searchParams.get('utm_source')).toBe(c.id)
    }
  })

  it('have no redirect to the hub that is not a channel’s', () => {
    const toHub = [...locations].filter(([, target]) => target.startsWith(LINKS_URL)).map(([path]) => path)
    expect(toHub.sort()).toEqual(CHANNELS.map((c) => c.short).sort())
  })

  it('are relative, and declare no headers of their own', () => {
    for (const c of CHANNELS) {
      expect(shortPathLocation(c).startsWith('/')).toBe(true)
      // One line each: an `add_header` would have to be inside the braces.
      const line = NGINX.split('\n').find((l) => l.includes(`location = ${c.short} `))!
      expect(line).not.toContain('add_header')
    }
    const hub = NGINX.match(/location \/links\/ \{([^}]*)\}/)
    expect(hub, 'the /links/ location').not.toBeNull()
    expect(hub![1]).toContain('expires -1;')
    expect(hub![1]).not.toContain('add_header')
  })

  it('share no path with an SPA route: nginx would take the route over', () => {
    const segments = new Set(
      [...ROUTER.matchAll(/\bpath:\s*'([^']*)'/g)].map((m) => m[1]!.replace(/^\//, '').split('/')[0]!),
    )
    expect(segments.size).toBeGreaterThan(20) // the parse found the route table
    for (const path of [...CHANNELS.map((c) => c.short), LINKS_URL]) {
      const segment = path.replace(/^\//, '').split('/')[0]!
      expect(segments.has(segment), `an SPA route answers /${segment}`).toBe(false)
    }
  })
})
