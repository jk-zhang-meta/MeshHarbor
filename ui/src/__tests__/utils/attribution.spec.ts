// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-88 (#1790) §3a — what the register view sends as `attribution`, and what
// the OAuth start URL and the newsletter carry. The load-bearing cases are the
// ones that fail silently: a campaign dropped on its way to the account, an
// empty object sent where nothing should be, a full referrer URL where only a
// host may go, and an oversized tag that could break a sign-in URL.
import { describe, expect, it } from 'vitest'
import {
  ATTRIBUTION_ENABLED,
  CAMPAIGN_KEYS,
  CARRIED_KEYS,
  MAX_VALUE_CHARS,
  SELF_REPORTED_OPTIONS,
  carriedQuery,
  externalHost,
  newsletterSource,
  oauthStartUrl,
  queryOf,
  signupAttribution,
} from '@/utils/attribution'

const HOST = 'meshharbor.itachi.fans'
const landing = { referrer: 'https://www.youtube.com/', host: HOST, path: '/register' }

describe('the contract', () => {
  it('is switched on, and carries exactly the documented keys', () => {
    expect(ATTRIBUTION_ENABLED).toBe(true)
    expect([...CAMPAIGN_KEYS]).toEqual(['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term', 'ref'])
    expect([...CARRIED_KEYS]).toEqual([...CAMPAIGN_KEYS, 'referrer_host', 'landing_path'])
    expect(MAX_VALUE_CHARS).toBe(64)
  })

  it('offers the spec’s answers to "How did you hear about MeshHarbor?"', () => {
    expect([...SELF_REPORTED_OPTIONS]).toEqual([
      'search',
      'youtube',
      'tiktok',
      'instagram',
      'facebook',
      'reddit',
      'hacker_news',
      'friend',
      'other',
    ])
  })
})

describe('signupAttribution', () => {
  it('sends NOTHING without a campaign or an answer: the key is omitted, not `{}`', () => {
    expect(signupAttribution({}, landing)).toBeUndefined()
    expect(signupAttribution({ invite: 'abc' }, landing)).toBeUndefined()
    // An external referrer alone is not a campaign.
    expect(signupAttribution({}, { ...landing, referrer: 'https://news.ycombinator.com/' })).toBeUndefined()
  })

  it('maps utm_* to the fields the server stores', () => {
    const a = signupAttribution(
      {
        utm_source: 'youtube',
        utm_medium: 'video',
        utm_campaign: 'fr88-test',
        utm_content: 'desc-link',
        utm_term: 'remote desktop',
      },
      landing,
    )
    expect(a).toEqual({
      source: 'youtube',
      medium: 'video',
      campaign: 'fr88-test',
      content: 'desc-link',
      term: 'remote desktop',
      referrer_host: 'www.youtube.com',
      landing_path: '/register',
    })
  })

  it('takes `ref` as the source only when utm_source is absent', () => {
    expect(signupAttribution({ ref: 'producthunt' }, landing)?.source).toBe('producthunt')
    expect(signupAttribution({ ref: 'producthunt', utm_source: 'youtube' }, landing)?.source).toBe('youtube')
  })

  it('keeps where the journey began when an earlier page carried it', () => {
    // A static page put both on the link; this page's own referrer is that
    // page, on this site, and must not overwrite them.
    const a = signupAttribution(
      { utm_source: 'youtube', referrer_host: 'www.youtube.com', landing_path: '/blog/x/' },
      { referrer: 'https://meshharbor.itachi.fans/blog/x/?utm_source=youtube', host: HOST, path: '/register' },
    )
    expect(a).toMatchObject({ referrer_host: 'www.youtube.com', landing_path: '/blog/x/' })
  })

  it('records no referrer for a visit from this site, or from nowhere', () => {
    expect(signupAttribution({ utm_source: 'x' }, { referrer: 'https://meshharbor.itachi.fans/', host: HOST, path: '/register' })).toEqual({
      source: 'x',
      landing_path: '/register',
    })
    expect(signupAttribution({ utm_source: 'x' }, { referrer: '', host: HOST, path: '/register' })).not.toHaveProperty(
      'referrer_host',
    )
  })

  it('ignores carried journey keys without a campaign: a bare link says nothing', () => {
    expect(signupAttribution({ referrer_host: 'evil.example', landing_path: '/x' }, landing)).toBeUndefined()
  })

  it('sends only non-empty values, trimmed and capped at 64 characters', () => {
    const a = signupAttribution(
      { utm_source: '  youtube  ', utm_medium: '   ', utm_campaign: 'c'.repeat(500), utm_term: '' },
      landing,
    )!
    expect(a.source).toBe('youtube')
    expect(a).not.toHaveProperty('medium')
    expect(a).not.toHaveProperty('term')
    expect(a.campaign).toBe('c'.repeat(64))
    for (const v of Object.values(a)) expect(v.length).toBeLessThanOrEqual(64)
    // No key is present with an undefined value either.
    expect(Object.values(a).every((v) => typeof v === 'string' && v.length > 0)).toBe(true)
  })

  it('takes the FIRST of a repeated key, as the static pages do', () => {
    expect(signupAttribution({ utm_source: ['first', 'second'] }, landing)?.source).toBe('first')
    expect(signupAttribution({ utm_source: [null, 'x'] }, landing)).toBeUndefined()
  })

  it('sends the optional answer with or without a campaign, and only a known one', () => {
    expect(signupAttribution({}, landing, 'youtube')).toEqual({ self_reported: 'youtube' })
    expect(signupAttribution({ utm_source: 'x' }, landing, 'friend')).toMatchObject({ source: 'x', self_reported: 'friend' })
    expect(signupAttribution({}, landing, null)).toBeUndefined()
    expect(signupAttribution({}, landing, 'something-else')).toBeUndefined()
  })
})

describe('carriedQuery — what a link onward from an SPA page carries', () => {
  it('is empty without a campaign, whatever else the URL holds', () => {
    expect(carriedQuery({}, landing)).toEqual({})
    expect(carriedQuery({ invite: 'abc', referrer_host: 'x', landing_path: '/y' }, landing)).toEqual({})
  })

  it('carries the campaign as it came, then where the journey began, in the static script’s order', () => {
    const q = carriedQuery({ ref: 'bio', utm_campaign: 'c1', utm_source: 'tiktok', invite: 'abc' }, { ...landing, path: '/login' })
    expect(q).toEqual({ utm_source: 'tiktok', utm_campaign: 'c1', ref: 'bio', referrer_host: 'www.youtube.com', landing_path: '/login' })
    expect(Object.keys(q)).toEqual(['utm_source', 'utm_campaign', 'ref', 'referrer_host', 'landing_path'])
    // Only carried keys: an invite code is not attribution.
    for (const k of Object.keys(q)) expect(CARRIED_KEYS as readonly string[]).toContain(k)
  })

  it('passes on what an earlier page carried rather than re-deriving it', () => {
    const q = carriedQuery(
      { utm_source: 'youtube', referrer_host: 'www.youtube.com', landing_path: '/blog/x/' },
      { referrer: 'https://meshharbor.itachi.fans/blog/x/', host: HOST, path: '/register' },
    )
    expect(q).toMatchObject({ referrer_host: 'www.youtube.com', landing_path: '/blog/x/' })
  })

  it('is what signupAttribution is built on, so a link and the request agree', () => {
    const query = { utm_source: 'youtube', utm_medium: 'video' }
    const onward = carriedQuery(query, landing)
    expect(signupAttribution(onward, { referrer: 'https://meshharbor.itachi.fans/register', host: HOST, path: '/login' })).toEqual(
      signupAttribution(query, landing),
    )
  })
})

describe('externalHost', () => {
  it('is the HOST, never the URL: a referrer can carry a search query or a private path', () => {
    expect(externalHost('https://www.google.com/search?q=private+words', HOST)).toBe('www.google.com')
    expect(externalHost('https://example.com:8443/a/b', HOST)).toBe('example.com:8443')
  })

  it('is undefined for this site, for none, and for one that does not parse', () => {
    expect(externalHost('https://meshharbor.itachi.fans/docs/', HOST)).toBeUndefined()
    expect(externalHost('', HOST)).toBeUndefined()
    expect(externalHost(undefined, HOST)).toBeUndefined()
    expect(externalHost('not a url', HOST)).toBeUndefined()
  })
})

describe('oauthStartUrl', () => {
  it('is the bare start URL without attribution', () => {
    expect(oauthStartUrl('google')).toBe('/api/oauth/google')
    expect(oauthStartUrl('github', {})).toBe('/api/oauth/github')
  })

  it('carries each field under the parameter `GET /api/oauth/{provider}` accepts, and nothing else', () => {
    const url = oauthStartUrl('google', {
      source: 'youtube',
      medium: 'video',
      campaign: 'c1',
      content: 'x',
      term: 'y',
      referrer_host: 'www.youtube.com',
      landing_path: '/blog/x/',
      self_reported: 'friend',
    })
    const u = new URL(url, 'https://meshharbor.itachi.fans')
    expect(u.pathname).toBe('/api/oauth/google')
    expect(Object.fromEntries(u.searchParams)).toEqual({
      utm_source: 'youtube',
      utm_medium: 'video',
      utm_campaign: 'c1',
      utm_content: 'x',
      utm_term: 'y',
      referrer_host: 'www.youtube.com',
      landing_path: '/blog/x/',
      self_reported: 'friend',
    })
  })

  it('encodes values, so a tag cannot inject a parameter', () => {
    const u = new URL(oauthStartUrl('google', { campaign: 'a&state=evil' }), 'https://meshharbor.itachi.fans')
    expect(u.searchParams.get('utm_campaign')).toBe('a&state=evil')
    expect(u.searchParams.has('state')).toBe(false)
  })
})

describe('newsletterSource', () => {
  it('is the form’s own source without a campaign', () => {
    expect(newsletterSource({}, 'landing')).toBe('landing')
    expect(newsletterSource({ utm_source: 'youtube' }, 'landing')).toBe('landing')
  })

  it('is the campaign when there is one, filtered as the server filters (32 chars of [A-Za-z0-9_-])', () => {
    expect(newsletterSource({ utm_campaign: 'fr88-launch_1' }, 'landing')).toBe('fr88-launch_1')
    expect(newsletterSource({ utm_campaign: 'a b<c>d' }, 'landing')).toBe('abcd')
    expect(newsletterSource({ utm_campaign: 'x'.repeat(40) }, 'landing')).toBe('x'.repeat(32))
  })

  it('keeps the form’s source when the campaign cleans to nothing', () => {
    expect(newsletterSource({ utm_campaign: '🎉 !' }, 'landing-footer')).toBe('landing-footer')
  })
})

describe('queryOf', () => {
  it('reads a location.search string, keeping the first of a repeated key', () => {
    expect(queryOf('?utm_source=a&utm_source=b&ref=c')).toEqual({ utm_source: 'a', ref: 'c' })
    expect(queryOf('')).toEqual({})
  })
})
