// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { appPath } from '@/utils/deployment'
/**
 * FR-88 (#1790) §3a — sign-up attribution: carry, don't store.
 *
 * A campaign link (`?utm_source=youtube&utm_campaign=…`, or `?ref=…`) says
 * where a visitor came from. The static pages copy those keys onto their own
 * sign-up, install and download links (`ui/docs/theme/attribution.js`); the
 * register view reads them from its URL and sends them ONCE, with the new
 * account, either in the register request or on the OAuth start URL (the
 * server parks them under the CSRF state it already mints).
 *
 * NOTHING about this is written to the visitor's device: no cookie, no
 * localStorage, no sessionStorage, no IndexedDB. Storing on a terminal for a
 * non-essential purpose needs consent under ePrivacy Art. 5(3); the site has
 * no consent banner and must not need one. The keys live in URLs, and every
 * function here reads a URL at the moment it is needed.
 *
 * Zero imports, like `enrollCommands.ts` and `landing.ts`, so the static-site
 * generator can read the kill switch below at build time.
 */

/**
 * The kill switch (FR-88 P1). `false`: the register view sends no
 * `attribution` and hides its question, the OAuth buttons carry nothing, the
 * newsletter keeps its own `source`, and the static pages stop loading the
 * carry script (the generator reads this).
 */
export const ATTRIBUTION_ENABLED = true

/** The campaign keys a link may carry. One of them being present is what
 *  turns carrying on; without one, nothing is carried and nothing is sent. */
export const CAMPAIGN_KEYS = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term', 'ref'] as const

/**
 * Every key a static page puts on a link, in order: the campaign, then where
 * the journey began.
 *
 * ⚠️ `ui/docs/theme/attribution.js` carries exactly these (it is plain
 * JavaScript and cannot import this file); `docs/__tests__/attribution.spec.ts`
 * locks the two equal.
 */
export const CARRIED_KEYS = [...CAMPAIGN_KEYS, 'referrer_host', 'landing_path'] as const

/** The server keeps 64 characters of each value (§3a). The client never sends
 *  more, which also keeps an OAuth start URL far from any URL-length limit:
 *  an oversized campaign tag must not be able to break a sign-in. */
export const MAX_VALUE_CHARS = 64

/** "How did you hear about Roomler?": the values sent as `self_reported`.
 *  The labels are i18n (`auth.heardAboutOptions.<value>`). */
export const SELF_REPORTED_OPTIONS = [
  'search',
  'youtube',
  'tiktok',
  'instagram',
  'facebook',
  'reddit',
  'hacker_news',
  'friend',
  'other',
] as const
export type SelfReported = (typeof SELF_REPORTED_OPTIONS)[number]

/** `POST /api/auth/register`'s optional `attribution` object. */
export interface SignupAttribution {
  source?: string
  medium?: string
  campaign?: string
  content?: string
  term?: string
  referrer_host?: string
  landing_path?: string
  self_reported?: string
}

/** A router `LocationQuery`, or `Object.fromEntries(new URLSearchParams(…))`. */
export type QueryLike = Readonly<Record<string, string | null | undefined | ReadonlyArray<string | null>>>

/** The page a query was read on, for the two keys only the FIRST page of a
 *  journey can work out. A later page gets both from the link it arrived by. */
export interface Landing {
  /** `document.referrer`. */
  referrer?: string
  /** `location.host` of the page reading the query. */
  host?: string
  /** The path of the page reading the query. */
  path?: string
}

function value(query: QueryLike, key: string): string | undefined {
  const raw = query[key]
  const v = Array.isArray(raw) ? raw[0] : raw
  if (typeof v !== 'string') return undefined
  const trimmed = v.trim()
  return trimmed ? trimmed.slice(0, MAX_VALUE_CHARS) : undefined
}

/** The HOST of a referrer from another site — never the full URL, which can
 *  carry a search query or a private path. Undefined for this site, for no
 *  referrer, and for one that does not parse. */
export function externalHost(referrer: string | undefined, host: string | undefined): string | undefined {
  if (!referrer) return undefined
  try {
    const h = new URL(referrer).host
    return h && h !== host ? h.slice(0, MAX_VALUE_CHARS) : undefined
  } catch {
    return undefined
  }
}

/**
 * The keys a link onward from this page carries, the same rule as the static
 * pages' `attribution.js`: the campaign as it came, then where the journey
 * began. `referrer_host` and `landing_path` come from the URL when an earlier
 * page of this site carried them, else from `landing`. Empty without a
 * campaign: without one the link says nothing about where the visitor came
 * from, and a link with nothing to carry is left as it is.
 *
 * ⚠️ Values that ARRIVE on the URL are taken as given, like any `utm_*`: any
 * link can set them. The server clamps them; nothing checks them. That is a
 * data-quality limit, not a security one (FR-88 §3a).
 */
export function carriedQuery(query: QueryLike, landing: Landing = {}): Record<string, string> {
  if (!ATTRIBUTION_ENABLED) return {}
  const out: Record<string, string> = {}
  for (const k of CAMPAIGN_KEYS) {
    const v = value(query, k)
    if (v !== undefined) out[k] = v
  }
  if (Object.keys(out).length === 0) return {}
  const referrer = value(query, 'referrer_host') ?? externalHost(landing.referrer, landing.host)
  if (referrer) out.referrer_host = referrer
  const path = value(query, 'landing_path') ?? (landing.path?.trim() || undefined)?.slice(0, MAX_VALUE_CHARS)
  if (path) out.landing_path = path
  return out
}

/**
 * What the register view sends as `attribution`, or `undefined` when there is
 * nothing to send (then the request carries no `attribution` key at all).
 *
 * - The campaign and where the journey began, by `carriedQuery`'s rule.
 * - `utm_source` is the source; `ref` stands in for it when it is absent.
 * - `self_reported` is the optional answer, sent with or without a campaign,
 *   and only when it is one of the offered options.
 */
export function signupAttribution(
  query: QueryLike,
  landing: Landing = {},
  selfReported?: string | null,
): SignupAttribution | undefined {
  if (!ATTRIBUTION_ENABLED) return undefined
  const c = carriedQuery(query, landing)
  const a: SignupAttribution = {
    source: c.utm_source ?? c.ref,
    medium: c.utm_medium,
    campaign: c.utm_campaign,
    content: c.utm_content,
    term: c.utm_term,
    referrer_host: c.referrer_host,
    landing_path: c.landing_path,
  }
  if (selfReported && (SELF_REPORTED_OPTIONS as readonly string[]).includes(selfReported)) {
    a.self_reported = selfReported
  }
  // Only the keys that have a value: an explicit `undefined` would still be a
  // key to anything that iterates the object before JSON drops it.
  const out = Object.fromEntries(Object.entries(a).filter(([, v]) => v !== undefined)) as SignupAttribution
  return Object.keys(out).length ? out : undefined
}

/** The OAuth start URL's parameter for each attribution field (the contract of
 *  `GET /api/oauth/{provider}`). */
const OAUTH_PARAMS: ReadonlyArray<readonly [keyof SignupAttribution, string]> = [
  ['source', 'utm_source'],
  ['medium', 'utm_medium'],
  ['campaign', 'utm_campaign'],
  ['content', 'utm_content'],
  ['term', 'utm_term'],
  ['referrer_host', 'referrer_host'],
  ['landing_path', 'landing_path'],
  ['self_reported', 'self_reported'],
]

/** `GET /api/oauth/{provider}`, carrying the attribution when there is any.
 *  The server holds it for the ten minutes a sign-in may take; a missing or
 *  expired value means "no attribution", never a failed login. */
export function oauthStartUrl(provider: string, attribution?: SignupAttribution): string {
  const base = appPath(`/api/oauth/${provider}`)
  if (!attribution) return base
  const params = new URLSearchParams()
  for (const [field, param] of OAUTH_PARAMS) {
    const v = attribution[field]
    if (v) params.set(param, v)
  }
  const qs = params.toString()
  return qs ? `${base}?${qs}` : base
}

/** Start a sign-in or sign-up with a provider, carrying the attribution.
 *  Both auth views use it: an OAuth "sign-in" from `/login` creates the
 *  account when there is none, and the server attaches the attribution only
 *  then. The one place the SPA leaves for the provider (and a seam for tests). */
export function startOAuth(provider: string, attribution?: SignupAttribution): void {
  window.location.href = oauthStartUrl(provider, attribution)
}

/**
 * The newsletter's `source`: the campaign when this visit carries one, else
 * the form's own. Filtered exactly as the server's `clean_source` filters
 * (`[A-Za-z0-9_-]`, 32 characters), so a campaign that cleans to nothing keeps
 * the form's source rather than becoming the server's "unknown".
 */
export function newsletterSource(query: QueryLike, fallback: string): string {
  if (!ATTRIBUTION_ENABLED) return fallback
  const campaign = (value(query, 'utm_campaign') ?? '').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32)
  return campaign || fallback
}

/** A `location.search` string as a `QueryLike`. A repeated key keeps its
 *  FIRST value, as `URLSearchParams.get` and the static carry script do. */
export function queryOf(search: string): QueryLike {
  const out: Record<string, string> = {}
  new URLSearchParams(search).forEach((v, k) => {
    if (!(k in out)) out[k] = v
  })
  return out
}
