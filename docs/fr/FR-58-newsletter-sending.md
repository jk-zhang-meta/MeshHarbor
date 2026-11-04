<!-- SPDX-License-Identifier: MPL-2.0 -->
# FR-58: Newsletter sending — the list exists, and nothing can mail it

**Status:** **CLOSED — field-verified on production, 2026-09-02** (deploy
`v20260901-bfc5f58ef358`; the full loop in the field-verification log below). P0–P5 merged
2026-09-01 (#1171 #1176 #1185 #1188 #1189 #1190). Tracking issue:
[#1170](https://github.com/gjovanov/roomler-ai/issues/1170).
Anchors verified against master `fc1ab18d` at claim time.

## Goal

FR-39 shipped the subscriber **list** — `Subscriber` model with double-opt-in tokens and
suppression rows, three public routes, four indexes, seven integration tests, a landing
capture form — and deferred the other half by name: *"Newsletter **sending**, templates,
and any analytics beyond the `source` field"* (`docs/fr/FR-39-launch-readiness.md:139`).

This FR is that program. An operator composes an issue from a canonical `.md` source
(the same file is the Medium post), previews the **exact** bytes a recipient would get,
test-sends to one address, then fans out to every confirmed subscriber with a
per-recipient one-click unsubscribe — idempotently, resumably, and honestly reported.
Alongside it: the auto-ask surfaces the list never got (the landing prompt, a profile
toggle, a dashboard card, a footer form), and the first ten issues, drafted in the
private annex.

## Field evidence

The list has been unreachable end-to-end since it shipped:

1. **Every landing subscription attempt 404s.**
   `ui/src/components/landing/StayInTouch.vue:75` posts `'/api/subscribe'` through
   `ui/src/api/client.ts`, whose `BASE_URL` is already `'/api'` (`client.ts:7`) — the wire
   request is `POST /api/api/subscribe`, the server 404s, and the catch branch shows
   *"Could not reach the server."* to every visitor. 🔑 No test layer could see it:
   integration tests hit the API directly, unit tests mock the client, and no e2e drives
   the form (`ui/e2e/email-flows.spec.ts` covers activation and mentions only). A unit
   test of a helper is not a test of the wiring — the FR-12 seed lesson, on its second
   surface.
2. **Confirm/unsubscribe outcomes are invisible.**
   `crates/api/src/routes/subscribe.rs:203-206` 303s to `{frontend_url}/?subscribe=…`,
   but `/` carries `meta:{auth:true}` and the router guard exact-matches
   `to.fullPath === '/'` (`ui/src/plugins/router.ts:274`): a logged-out confirmer is
   bounced to `/login` with sessionStorage noise, a signed-in one renders the dashboard,
   and the `SUBSCRIBE_MESSAGES` handler (`ui/src/views/LandingView.vue:320-333`) is dead
   code.
3. **P0 measures the prod consequences before anything is built**: subscriber counts by
   status (expected ≈0 given bug 1) and mailer health (is SendGrid's `api_key` set — do
   activation mails actually deliver?).

## Key design

### Send semantics

- **Claim-first per-recipient ledger.** `newsletter_sends` rows are inserted
  (`status: claimed`) *before* the send attempt; the unique index on
  `{issue_id, subscriber_id}` arbitrates. Email is the canonical at-most-once workload: a
  duplicate newsletter is a visible spam-report event, a missed recipient is a detectable
  stuck row. 🔑 **The unique index is the invariant; the issue-level claim is only an
  efficiency gate** — even if two pods ever fanned out concurrently, per-recipient insert
  races resolve to one winner.
- **Stuck claims are reported, never auto-retried.** A row stuck `claimed` (crash after
  the provider's 202, before `mark_sent`) is genuinely ambiguous — auto-retry converts
  "maybe delivered" into "maybe delivered twice" without a human deciding. Status lists
  them as `stale`; `{retry_stale: true}` on a resume POST re-attempts them via per-row
  CAS, as an explicit operator decision. The stranded set is bounded by the send
  concurrency (≤4 per crash).
- **Terminal status is `Completed`, never `sent`.** An issue whose every row failed still
  terminates, and calling that state "sent" would lie; counts
  `{total, sent, failed, suppressed, stale}` carry the truth. ⚠️ Ledger `sent` means
  "accepted by the backend" — a SendGrid 202 is not delivery, and the status payload says
  so.
- **Snapshot + per-recipient re-check.** The recipient set is `mailable()`'s Vec at send
  time (fine to ~50k; revisit paging then). Mid-send *confirms* wait for the next issue —
  otherwise trickling confirmations make completion unreachable. Mid-send *unsubscribes*
  are honored: each recipient is re-fetched at claim time and marked `suppressed` if
  withdrawn.
- **Pre-render once, substitute per recipient.** The issue renders to HTML once with a
  `%%UNSUBSCRIBE_URL%%` placeholder; each recipient gets byte-identical content except
  their link — so **preview IS the sent artifact**, not a sibling of it.
- ⚠️ **A 30 s `tokio::time::timeout` wraps every send and is load-bearing**: the SendGrid
  path's `reqwest::Client::new()` (`crates/services/src/email.rs:79`) has no default
  timeout, and one hung connection would otherwise wedge a semaphore slot — and the
  fan-out — forever, with a live heartbeat masking it.
- **Refuse loudly with no mailer**: send answers 400 before any claim when
  `state.email` is `None` — ledgering an entire list into `failed` on a misconfigured pod
  is worse than refusing.
- **Rejected, and why** (recorded so the next reader doesn't re-litigate):
  `background_tasks` is a bare `tokio::spawn` with required `tenant_id`/`user_id`, no
  retry, no crash recovery, no leader gate — and its progress record would duplicate the
  ledger, which is the real progress record. Redis `try_claim`
  (`crates/api/src/ws/redis_pubsub.rs:237`) is skip-a-cycle semantics for idempotent
  sweeps, not a must-send-once claim. Coordination is Mongo CAS + the ledger, and
  survives a Redis outage.

### One-click unsubscribe (RFC 8058)

Every issue carries `List-Unsubscribe: <https://…/api/subscribe/unsubscribe/{token}>` and
`List-Unsubscribe-Post: List-Unsubscribe=One-Click`. The POST target is method-routed
onto the **existing** token path — `get(unsubscribe).post(unsubscribe_oneclick)` — so one
URL, one token, one DAO call serve both the human link and the provider button. The POST
answers plain 200 for every outcome (providers want a 2xx, follow no redirects, and a
miss must not become a membership oracle) and discards the form body unread — an
extractor that 415s on content-type would break providers. `EmailService` grows a
`send_ext(to, subject, html, opts)` with per-message headers and From override; the
existing `send` delegates, so the seven transactional callers are untouched.

### Composition and rendering

- Issues are authored as `.md` (canonical source, doubles as the Medium post) and
  submitted with metadata (subject, preheader, hero URL, CTA text/URL) to platform-admin
  CRUD routes. Explicit create + update-while-draft — not upsert: a typo'd slug must 404,
  not mint a second issue.
- **`pulldown-cmark` with raw-HTML events dropped structurally**
  (`Event::Html | Event::InlineHtml` filtered before `push_html`): the only HTML in a
  body is renderer-emitted, so a pasted export cannot smuggle tags, pixels or foreign
  styling — and it is less code than sanitizing. No markdown renderer exists in the Rust
  tree today; this is the first.
- The branded wrapper is a `format!` template like every existing mail: 600 px table,
  landing palette (teal `#009688`/`#00796B`, ink `#1a1a2e`, light-only), optional hero
  `<img>`, optional CTA button, and a footer with the company identity, the unsubscribe
  link, *"you subscribed at roomler.ai"* — and **no tracking pixels**, stated in the
  footer, because `source` remains the only analytics (FR-39's line, kept).
- ⚠️ Subject/preheader are stripped of control characters and length-capped at the
  route: a `\r\n` in a subject is SMTP header injection on the lettre backend. Every
  operator string entering the wrapper passes a (new, first-in-tree) `escape_html`.
- A separate newsletter From (`MESHHARBOR__NEWSLETTER__FROM_EMAIL`/`__FROM_NAME`, fallback
  to `email.from_*`) isolates campaign reputation from transactional (activation) mail.

### Gate

Every admin route's first line is `require_platform_admin`
(`crates/api/src/routes/stats.rs:39-45`): the existing ObjectId allowlist, 404-on-miss —
never 403, which the web client answers with a forced logout. `platform_admins` unset ⇒
the entire admin surface 404s; that inherent gate is the kill switch, and a second
config flag guarding the same door would be a second switch to forget.

### Subscribe surfaces

- Fix the two capture bugs; repoint the 303s at new public outcome pages
  `/newsletter/confirmed` + `/newsletter/unsubscribed` — the `/consent/:token` route
  shape (`router.ts:58-65`): **no `meta.auth`, no `meta.guest`** (guest would bounce a
  signed-in unsubscriber to the dashboard), registered above the catch-all, render-only.
- **Deferred landing prompt**: a dismissible card after ~60 % scroll or ~20 s, once ever —
  flat `roomler-newsletter-dismissed` latch (an anonymous visitor has no user id), every
  storage access try/caught, unreadable storage ⇒ treated as dismissed (fail toward not
  annoying — the `useTutorialProgress` house rules). Never a blocking modal.
- **Profile toggle + dashboard card** for signed-in users ride a new authed path that
  inserts the account's own verified email as a **pre-confirmed** subscriber
  (`source: "account"` — ownership is already proven, so no confirmation mail).
  🔑 `subscribers` stays the only membership store: `models/subscriber.rs:9-13` forbids
  folding this into `User`, and `NotificationPrefs.email` is transactional @mention
  routing, not marketing consent — overloading it would silently unsubscribe people from
  mentions or vice versa.
- **Footer form**: a light-surface variant of `StayInTouch` (today it is styled for the
  teal CTA parent).

### Content (the ten issues)

Drafts, editorial calendar and hero sources live in the **private annex**
(`roomler-ai-news`: `news/` = the campaign queue, `fixes/` = engineering war stories on their own schedule), per the FR-39 scope rule — post copy is not an
engineering artifact and does not live in a public repo. What is engineering and stays
here: heroes follow the tutorial artwork contract (locked landing palette, flat vector,
light-surface — stated in `ui/src/assets/tutorial/*.svg`), are **rendered headless to
PNG and looked at** (the FR-12 method: four real defects were invisible in SVG source),
at 1200×630 so each doubles as the Medium/OG card; emails ship the PNG raster (mail
clients strip SVG and `<style>`). Shipped images land in
`ui/public/newsletter-img/<slug>-v1.png` — the nginx static-extension location
(`files/nginx-pod.conf:65-69`) beats the SPA fallback and serves them with a 1-year
immutable cache, so **filenames are versioned and never edited in place**.

## Phases

| P | Scope | Kill switch |
|---|---|---|
| P0 | Claim + spec. **Measure prod**: subscriber counts by status; mailer health. | n/a |
| P1 | List plumbing: the two capture-bug fixes, public outcome pages, redirect repoint, RFC-8058 one-click POST, `send_ext` headers/From plumbing. | none needed — bug fixes plus inert plumbing |
| P2 | `newsletter_issues` model + renderer (`pulldown-cmark`, raw HTML dropped) + admin CRUD / preview / test-send. | `platform_admins` unset ⇒ every route 404s (inherent) |
| P3 | `newsletter_sends` ledger + fan-out + status/resume. | no mailer ⇒ send refuses 400 before any claim; the issue CAS makes duplicate POSTs inert |
| P4 | Auto-ask surfaces + the authed pre-confirmed subscribe path. | localStorage latches; the authed route is inert if unused |
| P5 | The ten issues + heroes (private annex) + `ui/public/newsletter-img/` + `docs/newsletter.md` + `docs/README.md` row + `docs/api.md` / `.env.example` housekeeping + the operator send script. | content only |
| P6 | Field verification on prod (below). | — |

## Acceptance criteria

- [x] P0 produced numbers: prod subscriber counts by status (**0 rows ever** — the 404
      bug measured at population level) and a mailer-health verdict (SendGrid configured,
      delivering), recorded on the issue before P1 merged.
- [x] A visitor can subscribe on the live landing page — shown to **fail** on the
      pre-fix deploy first (the prod zero IS that measurement). Field 2026-09-02: a real
      Playwright click on the live form → `POST /api/subscribe` → 202 → the first
      subscriber row the collection has ever held; the confirmation mail landed in the
      Gmail INBOX (not spam); `/newsletter/confirmed` renders "You're on the list".
      ⚠️ Finding: the row confirmed **without a human click** — Gmail's link scanner
      followed the GET on delivery (see Open decisions).
- [x] Issue #1 sent to the real list from its `.md` source; ledger counts matched the
      status payload exactly (`{total:1, sent:1}` → `completed`); preview bytes equal
      sent bytes by construction and every marker was asserted on the live preview.
      Delivered to the Gmail INBOX as "Roomler Field Notes" (the configmap From override
      live).
- [x] One-click unsubscribe verified with the address's real token via the exact
      RFC-8058 provider POST (200, idempotent, row stamped), and a second send provably
      skipped the address — the probe issue completed `{total:0}`, zero ledger rows.
      (The Gmail-UI unsubscribe chip itself awaits a human glance — the automated
      session could not open Gmail's message view.)
- [x] Re-POSTing send never double-sends — integration-tested with an NXDOMAIN mailer
      (ledger rows prove the skip; completed is terminal), and a live second claim
      answers 409 naming the holder.
- [x] Every admin newsletter route answers 404 to a non-platform-admin caller and to an
      unset allowlist (both arms integration-tested; the allowlisted id passes).
- [x] Raw HTML in a body `.md` never reaches the rendered email (structural; unit-tested
      with `<script>`, `<img onerror>`, and inline tags; re-asserted on the preview
      route).
- [x] All four subscribe surfaces are live **on prod** (2026-09-02): the deferred prompt
      rendered in a fully anonymous headless session; the CTA + footer forms screenshot;
      the dashboard card appeared for the unsubscribed account and its "Keep me posted"
      re-subscribed it (`source: account`); the profile toggle read back ON. The latch
      behavior (incl. localStorage-throws) is unit-tested.
- [x] The stale-claim path is exercised: a manufactured stuck row is *reported*, survives
      a plain resume untouched, and is re-attempted only under `{retry_stale: true}` —
      whose re-check honors a withdrawal that happened while the row sat stuck.

## Open decisions

- ✅ **RESOLVED — field finding (2026-09-02): GET-confirm was prefetch-confirmable.** The
  very first real confirmation was performed by **Gmail's link scanner**, not a human —
  the row flipped and the single-use token burned before anyone clicked. Fixed the same
  night: the mail now links to `/newsletter/confirm/{token}` (a page whose **button
  POSTs** — merely loading it performs no request at all, unit-pinned), the GET became a
  pure redirect to that page (old in-flight links keep working at the cost of one
  deliberate click, and the handler doesn't even read the DB), and
  `a_prefetched_get_confirms_nothing_and_the_post_is_the_click` pins the whole shape.
  The consent flow's prefetcher note now has its second confirmed field case.
- Whether the one-click POST should move beside the governor-exempt webhook mounts:
  provider IPs are few and a 429'd unsubscribe is a deliverability black mark. Accepted
  behind the per-IP governor at current scale; recorded here so the move is a one-liner
  when scale demands it.
- A minimal platform-admin compose/send UI page later, on the same routes (v1 is API +
  an operator script from the annex sources).
- An e2e Mailpit journey (subscribe → confirm → unsubscribe) in `email-flows.spec.ts`.
- Whether `roomler.ai` should eventually render a public archive of past issues (today:
  out of scope).

## Out of scope

- Campaign tactics, channel timing, post copy — the annex, per FR-39's own scope rule.
- Open/click tracking, pixels, per-recipient links beyond the unsubscribe token
  (`source` stays the only analytics; the footer says so).
- Per-subscriber locale or timezone scheduling; digests; any unification with
  transactional mail.
- Automated resume of a send interrupted by a rolling deploy — the spawned task dies
  silently with the pod, status shows the stale heartbeat, and recovery is a deliberate
  operator re-POST. Don't deploy mid-send; documented, not automated.

## Ops notes (carried here so P6 doesn't rediscover them)

- ⚠️ SendGrid account-level **subscription tracking must be OFF** or it injects its own
  List-Unsubscribe alongside ours.
- ⚠️ The newsletter From address needs SPF/DKIM domain authentication **before the first
  real send**, or the campaign lands in spam and drags `noreply@`'s transactional
  reputation down with it.

## Field-verification log

| date | what was checked | result |
|---|---|---|
| 2026-09-01 | P0 prod measures | subscribers = **0 rows ever** (the 404 measured at population level); SendGrid configured + delivering; `platform_admins` already set |
| 2026-09-02 | Deploy `v20260901-bfc5f58ef358` (HEAD `e8e72131`) | both pods rolled, health 200; configmap `MESHHARBOR__NEWSLETTER__FROM_NAME` live |
| 2026-09-02 | Anonymous surfaces (fresh-profile headless Chrome) | deferred prompt rendered bottom-right; CTA + footer forms present; served bundle carries the latch key |
| 2026-09-02 | Real form click (Playwright, live landing) | `POST https://roomler.ai/api/subscribe` → **202** — the wire path that had 404'd for months; first subscriber row ever created |
| 2026-09-02 | Confirmation mail | landed in Gmail **INBOX**; ⚠️ confirmed by Gmail's link scanner before any human click (finding above); token burned single-use; outcome page renders |
| 2026-09-02 | Issue #1 (`three-products-one-daemon`) from its `.md` | create 201 → preview verified (branded, substituted, no raw HTML) → test-send `{sent:true}` → send 202 → `completed {total:1, sent:1}`; delivered to the inbox as **"Roomler Field Notes"** |
| 2026-09-02 | RFC-8058 one-click (real token, provider-shaped POST ×2) | 200 + 200 (idempotent), row stamped `unsubscribed_at` |
| 2026-09-02 | Suppression | probe issue → `completed {total:0}`, **zero** ledger rows for the unsubscribed address |
| 2026-09-02 | Signed-in door | dashboard card shown for the unsubscribed account → "Keep me posted" → `{subscribed:true}`, row revived `source: account`; profile toggle reads ON |
| 2026-09-02 | End state | 1 mailable subscriber (the operator, restored), `newsletter_sends` = exactly 1 honest `sent` row, 2 issues (the real one + the probe) |
