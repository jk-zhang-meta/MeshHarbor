<!-- SPDX-License-Identifier: MPL-2.0 -->
# Newsletter — the subscriber list and the sending program

FR-39 built the list; FR-58 built the publisher. This doc is the operator's view of both.
Spec: [`docs/fr/FR-58-newsletter-sending.md`](fr/FR-58-newsletter-sending.md).

## The list (public surface)

| Route | What it does |
|---|---|
| `POST /api/subscribe` `{email, source?}` | Always **202**, every outcome — a response that distinguished "new" from "already subscribed" would be a membership oracle for addresses that are usually also `users.email`. Stores the row unconfirmed, mails a confirm link (15-min per-address resend cooldown — the mail-bomb guard). |
| `GET /api/subscribe/confirm/{token}` | **Pure redirect** to `/newsletter/confirm/{token}` — never confirms. Mailbox link scanners follow GETs (Gmail's burned the first field subscriber's token before any human clicked), so the page button's **POST** is the deliberate click: single-use, `{confirmed: bool}`. |
| `GET /api/subscribe/unsubscribe/{token}` | Idempotent (mail clients prefetch). 303 → `/newsletter/unsubscribed?status=…`. The token never expires — a two-year-old email's link must still work. FR-102 P5: an issue's link adds `?i=<slug>` (the same for every recipient), and the click that ends the subscription stamps `unsubscribed_via` — once; a repeat changes nothing. |
| `POST /api/subscribe/unsubscribe/{token}` | The RFC 8058 one-click target (`List-Unsubscribe-Post`). Plain 200 for every outcome, body unread; the header carries the same link, `i=` included. |
| `POST /api/sendgrid/webhook` | FR-102 P5 — SendGrid's **signed** Event Webhook: `delivered`, `bounce`, `dropped`, `spamreport` onto the issue's ledger rows; a hard bounce or a spam report suppresses the address. Refused (401) before the body is parsed unless the ECDSA signature verifies; 404 for everything without a key. See [growth-observability.md](growth-observability.md#the-newsletter-delivery-per-issue-tags-and-unsubscribes-p5). |

Unsubscribed rows are **kept and stamped**, never deleted — the suppression list is the
consent record, and re-subscribing after a withdrawal always requires confirming again.
A **suppressed** row (SendGrid reported a hard bounce or a spam report — FR-102 P5) stays on
the list but is never mailed: the fan-out marks its ledger row `suppressed`. Subscribing
again (and confirming) or the signed-in toggle lifts it.

## Issues and sending (platform-admin surface)

Everything under `/api/admin/newsletter/*` is gated by the existing
`MESHHARBOR__STATS__PLATFORM_ADMINS` ObjectId allowlist and answers **404** on missing
authority (never 403 — the allowlist is itself what is being hidden, and a 403 would
confirm the surface exists). Allowlist unset ⇒ the whole
surface does not exist; that inherent gate is the kill switch.

> ⚠️ This 404 was once *also* justified by "the web client force-logs-out on 403".
> It does not any more — see [permissions.md](permissions.md) (FR-82). The reason
> above is the one that was always the real one.

| Route | What it does |
|---|---|
| `POST /issues` / `PUT /issues/{slug}` | Create a draft / edit **while draft**. Explicit create — a typo'd slug 404s, never upserts. Slug uniqueness is index-arbitrated (409). FR-102 P5: an optional `audience` (1–20 addresses) makes it a **test issue** — the send goes only to the confirmed subscribers among them, never the list; fixed with the draft, so a resumed send cannot widen it. |
| `GET /issues` / `GET /issues/{slug}` | List / read back. |
| `GET /issues/{slug}/preview` | The **exact** send-path bytes (sample unsubscribe link substituted). Preview IS the sent artifact, because the fan-out pre-renders once and substitutes per recipient. |
| `POST /issues/{slug}/test-send` `{email}` | Render + send to one address with the real headers. No ledger, honest failures. |
| `POST /issues/{slug}/send` `{retry_stale?}` | Claim the issue (`draft` → `sending`, CAS; a stale claim >10 min may be re-claimed = resume) and fan out. 400 when no mailer is configured — refusing beats ledgering a whole list into `failed`. |
| `GET /issues/{slug}/status` | Live counts while sending, stored counts once `completed`, stale rows listed by address. |

Drive it with [`scripts/newsletter-send.py`](../scripts/newsletter-send.py) from the
issue's canonical `.md` source (frontmatter + markdown body).

### Send semantics worth knowing before the first real send

- **Per-recipient ledger** (`newsletter_sends`, unique `{issue_id, subscriber_id}`):
  claim-first, so re-POSTing `send` never double-sends — the unique index is the
  invariant, the issue claim only an efficiency gate.
- **Stuck `claimed` rows are reported, never auto-retried** — a crash between the mail
  backend's accept and our mark is genuinely ambiguous. `{"retry_stale": true}` is the
  explicit operator decision to re-attempt them.
- **Terminal status is `completed`, never "sent"** — counts
  `{total, sent, failed, suppressed, stale}` carry the truth, and ledger `sent` means
  "accepted by the backend", not delivered.
- The recipient set is a **snapshot at send time**; mid-send *unsubscribes* are honored
  (re-checked per recipient), mid-send *confirms* wait for the next issue. A suppressed
  address (FR-102 P5) is re-checked the same way and never mailed.
- **What one issue did** (FR-102 P5): the ledger's `delivery` field carries what SendGrid's
  Event Webhook reported — delivered, bounced (hard or blocked), dropped, spam report — and
  `GET /api/admin/growth/newsletter` turns it into the per-issue table, beside the visits
  and sign-ups the issue's tagged links brought. Opens and clicks are never recorded.
- Markdown bodies render with **raw HTML dropped structurally** — anything not
  expressible in markdown silently vanishes, by design.
- A rolling deploy mid-send kills the fan-out task silently; status shows the stale
  heartbeat and recovery is re-POSTing `send`. Don't deploy mid-send.

## Configuration

| Key | Meaning |
|---|---|
| `MESHHARBOR__NEWSLETTER__FROM_EMAIL` / `__FROM_NAME` | The campaign From (falls back per-field to `MESHHARBOR__EMAIL__FROM_*`). Kept separate so campaign reputation can't drag the transactional From down. |
| `MESHHARBOR__EMAIL__API_KEY` or `__SMTP_HOST`+`__SMTP_PORT` | The mail backend (SendGrid / SMTP). Absent ⇒ subscribe still stores rows (unconfirmed), send refuses. |
| `MESHHARBOR__STATS__PLATFORM_ADMINS` | The admin allowlist (ObjectIds, comma-separated — ids, not emails). |
| `MESHHARBOR__NEWSLETTER__EVENT_WEBHOOK_PUBLIC_KEY` | FR-102 P5 — the key SendGrid signs its Event Webhook with (base64 DER, as SendGrid shows it, or PEM). Empty (default) ⇒ the webhook answers 404 and delivery reads "not measured". |
| `MESHHARBOR__NEWSLETTER__LINK_TAGS` | FR-102 P5 — the per-issue UTM tags on links to this site. Default `true`. |

## Ops prerequisites for a real campaign

- ⚠️ **SPF/DKIM domain authentication for the newsletter From** before the first real
  send — or the campaign lands in spam and drags the transactional From's reputation
  down with it.
- ⚠️ If SendGrid's account-level **subscription tracking** is on, it injects its own
  List-Unsubscribe next to ours — turn it off. (Since FR-102 P5 every newsletter message
  also switches subscription, open, click and Google Analytics tracking off in the request
  itself; the account setting still governs every other mail.)
- **Delivery events** (FR-102 P5): in SendGrid → Mail Settings → Event Webhook, POST to
  `https://meshharbor.itachi.fans/api/sendgrid/webhook` with **Delivered, Bounced, Dropped, Spam
  Reports** selected (never Opened or Clicked), enable **Signature Verification** and put
  the public key it shows in `MESHHARBOR__NEWSLETTER__EVENT_WEBHOOK_PUBLIC_KEY`. At boot the
  module reads the account's open/click tracking and logs a WARN if either is on — give the
  API key the `tracking_settings.read` scope so it can.
- Hero images ship as versioned files under `ui/public/newsletter-img/<slug>-vN.png`
  (the static-extension nginx location serves them with a 1-year immutable cache —
  never edit one in place, bump the version).
- **No tracking pixels, nothing per reader** — the email footer's promise ("the only
  per-recipient thing in this email is your unsubscribe link") is literally true. FR-102 P5
  counts each **issue**: its links to meshharbor.itachi.fans carry `utm_source=newsletter&utm_medium=email&
  utm_campaign=nl-<slug>`, identical for every recipient (rendered before the per-recipient
  substitution, and pinned by a test that two recipients' messages differ only in the
  unsubscribe link); the unsubscribe link adds `i=<slug>`; SendGrid's delivery events are
  recorded per message for delivery, bounces, drops and spam reports — never opens or clicks.
  This is a product stance (FR-39, FR-102 D5/D6), not a missing feature.
