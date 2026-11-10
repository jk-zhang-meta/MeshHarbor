// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-102 (#2127) — `loadAnalytics()` with no arguments, as `main.ts` calls
 * it, on a page served at https://meshharbor.itachi.fans. A document's location cannot
 * be changed once it exists (jsdom defines it unforgeable, as a browser
 * does), so this file alone runs on that URL; `analytics.spec.ts` covers the
 * same call on the suite's default `http://localhost:3000/`, where it loads
 * nothing.
 *
 * @vitest-environment jsdom
 * @vitest-environment-options { "url": "https://meshharbor.itachi.fans/login" }
 */
import { describe, expect, it } from 'vitest'
import { loadAnalytics } from '@/utils/analytics'

describe('loadAnalytics on the hosted site', () => {
  it('reads the page’s own location and injects the tracker, once', () => {
    expect(window.location.href).toBe('https://meshharbor.itachi.fans/login')
    // jsdom has no `webdriver` at all (undefined), which the rule reads as "not driven".
    expect(navigator.webdriver).not.toBe(true)
    expect(loadAnalytics()).toBe(true)
    const tags = document.querySelectorAll('script[src^="https://purestat.ai/"]')
    expect(tags).toHaveLength(1)
    const tag = tags[0] as HTMLScriptElement
    expect(tag.parentElement).toBe(document.head)
    expect(tag.defer).toBe(true)
    expect(tag.getAttribute('data-domain')).toBe('meshharbor.itachi.fans')
    expect(tag.getAttribute('src')).toBe('https://purestat.ai/js/purestat.js')
  })
})
