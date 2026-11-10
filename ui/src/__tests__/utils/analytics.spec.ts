// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-102 (#2127) §3c — the SPA loads purestat on the hosted site, and nowhere
 * else. Before this, `ui/index.html` carried the tag outright: every
 * self-hosted install, fork and `localhost` run beaconed as `meshharbor.itachi.fans`
 * (42 % of 90 days of events, measured). The rule is stated here case by
 * case; `docs/__tests__/analytics.spec.ts` holds the static pages' plain-JS
 * loader to the same table.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ANALYTICS_DOMAIN,
  ANALYTICS_HOSTS,
  ANALYTICS_SRC,
  loadAnalytics,
  shouldLoadAnalytics,
  type Where,
} from '@/utils/analytics'
import { CASES } from './analytics.cases'

const UI = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

describe('shouldLoadAnalytics — the rule', () => {
  it.each(CASES)('%s → %s', (_, where, loads) => {
    expect(shouldLoadAnalytics(where)).toBe(loads)
  })

  it('defaults to the two hostnames of the hosted site, and nothing else', () => {
    expect(ANALYTICS_HOSTS).toEqual(['meshharbor.itachi.fans', 'www.meshharbor.itachi.fans'])
    expect(ANALYTICS_SRC).toBe('https://purestat.ai/js/purestat.js')
    expect(ANALYTICS_DOMAIN).toBe('meshharbor.itachi.fans')
  })

  it('takes the allowlist as an argument: an empty one loads nowhere (the kill switch)', () => {
    const hosted: Where = { hostname: 'meshharbor.itachi.fans', protocol: 'https:', webdriver: false }
    expect(shouldLoadAnalytics(hosted, [])).toBe(false)
    expect(shouldLoadAnalytics({ ...hosted, hostname: 'docs.example' }, ['docs.example'])).toBe(true)
  })
})

// ── loadAnalytics: what it puts in the page, and what it must not touch ──

let spies: Array<ReturnType<typeof vi.spyOn>> = []
const idb = { open: vi.fn(), deleteDatabase: vi.fn() }

beforeEach(() => {
  spies = [
    vi.spyOn(Storage.prototype, 'setItem'),
    vi.spyOn(Storage.prototype, 'getItem'),
    vi.spyOn(Storage.prototype, 'removeItem'),
    vi.spyOn(Storage.prototype, 'clear'),
    vi.spyOn(Document.prototype, 'cookie', 'set'),
    vi.spyOn(Document.prototype, 'cookie', 'get'),
  ]
  vi.stubGlobal('indexedDB', idb)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  idb.open.mockReset()
  idb.deleteDatabase.mockReset()
})

function expectNoStorage(): void {
  for (const s of spies) expect(s, 'a storage API was touched').not.toHaveBeenCalled()
  expect(idb.open).not.toHaveBeenCalled()
  expect(idb.deleteDatabase).not.toHaveBeenCalled()
}

const blank = () => new DOMParser().parseFromString('<!DOCTYPE html><html><head><title>x</title></head><body></body></html>', 'text/html')
const trackers = (doc: Document) => [...doc.querySelectorAll('script[src^="https://purestat.ai/"]')]

describe('loadAnalytics', () => {
  it('injects exactly the tag the hosted site always carried, deferred, into <head>', () => {
    const doc = blank()
    expect(loadAnalytics(doc, { hostname: 'meshharbor.itachi.fans', protocol: 'https:', webdriver: false })).toBe(true)
    const tags = trackers(doc)
    expect(tags).toHaveLength(1)
    const tag = tags[0] as HTMLScriptElement
    expect(tag.parentElement).toBe(doc.head)
    expect(tag.defer).toBe(true)
    expect(tag.getAttribute('data-domain')).toBe('meshharbor.itachi.fans')
    expect(tag.getAttribute('src')).toBe('https://purestat.ai/js/purestat.js')
    expect(tag.getAttribute('type')).toBeNull() // a classic script: purestat reads document.currentScript
    expectNoStorage()
  })

  it.each(CASES.filter(([, , loads]) => !loads))('injects nothing on %s', (_, where) => {
    const doc = blank()
    const before = doc.documentElement.outerHTML
    expect(loadAnalytics(doc, where)).toBe(false)
    expect(trackers(doc)).toHaveLength(0)
    expect(doc.documentElement.outerHTML).toBe(before)
    expectNoStorage()
  })

  it('reads the page’s own location when none is given: this test run, on localhost, loads nothing', () => {
    // jsdom serves the suite at http://localhost:3000/ — a dev or test run.
    // The hosted-site half of this is `analytics.hosted.spec.ts`: a document's
    // location cannot be changed once it exists, so that file runs on the URL.
    expect(window.location.protocol).toBe('http:')
    expect(loadAnalytics(document)).toBe(false)
    expect(trackers(document)).toHaveLength(0)
  })

  it('never throws: a document that cannot take the tag is a false, not a broken app', () => {
    const doc = blank()
    doc.createElement = () => {
      throw new Error('boom')
    }
    expect(loadAnalytics(doc, { hostname: 'meshharbor.itachi.fans', protocol: 'https:', webdriver: false })).toBe(false)
    const noLocation = blank() // a DOMParser document has no browsing context, so no location
    expect(loadAnalytics(noLocation)).toBe(false)
  })
})

// ── the regression guards ─────────────────────────────────────────────────

describe('the SPA shell', () => {
  it('ui/index.html carries no analytics tag — its only script is its own module', () => {
    const html = readFileSync(join(UI, 'index.html'), 'utf8')
    expect(html.toLowerCase()).not.toContain('purestat')
    expect(html.match(/<script\b[^>]*>/g)).toEqual(['<script type="module" src="/src/main.ts">'])
  })

  it('main.ts calls the loader', () => {
    const main = readFileSync(join(UI, 'src', 'main.ts'), 'utf8')
    expect(main).toContain("import { loadAnalytics } from '@/utils/analytics'")
    expect(main).toMatch(/^loadAnalytics\(\)$/m)
  })
})
