# API Reference

Every HTTP endpoint the server exposes, grouped the way `build_router`
(`crates/api/src/lib.rs`) composes them. *As of 0.3.0-rc.381 the surface is ~165
endpoints across 38 route modules.* Request/response schemas are shown for the key
flows; for everything else the handler modules in `crates/api/src/routes/` are the
source of truth.

- **Base URL**: `https://roomler.ai` (or your deployment). All JSON.
- **IDs** are MongoDB ObjectIds serialized as 24-char hex strings.
- **Errors** are JSON with an HTTP status; 404 is also used to *hide* resources the
  caller may not see (platform-admin routes).

## Authentication

JWT bearer tokens (`Authorization: Bearer <jwt>`), Argon2 password hashing. Six
audience-checked token types — a token of one audience is rejected everywhere else:

| Token | Audience | Lifetime | Held by |
|---|---|---|---|
| `Access` | user routes + `/ws` (user role) | 7 d (config) | browser |
| `Refresh` | `POST /api/auth/refresh` only | 30 d (config) | browser |
| `Enrollment` | `POST /api/agent/enroll` | 10 min, single-use (`jti`) | pasted into installer |
| `Agent` | `/ws?role=agent`, agent ingest routes, `/derp` | long-lived | `roomlerd` config |
| `TunnelEnrollment` | `POST /api/tunnel-client/enroll` | 10 min, single-use | pasted into CLI |
| `TunnelClient` | `/ws?role=tunnel-client`, tunnel routes | long-lived | `roomler` CLI config |

```mermaid
sequenceDiagram
    participant B as Browser
    participant S as API

    B->>S: POST /api/auth/login {email|username, password}
    S-->>B: {access_token, refresh_token, user}
    B->>S: GET /api/... (Authorization: Bearer access)
    Note over B,S: access token expires
    B->>S: POST /api/auth/refresh {refresh_token}
    S-->>B: {access_token, refresh_token}
```

Device enrollment is a two-step exchange — an admin mints a short-lived token, the
installer trades it for the device's long-lived credential:

```mermaid
sequenceDiagram
    participant A as Admin (browser)
    participant S as API
    participant D as New machine (roomlerd)

    A->>S: POST /api/tenant/{tid}/agent/enroll-token
    S-->>A: {enrollment_token, expires_in: 600, jti}
    A-->>D: token handed to installer / wizard
    D->>S: POST /api/agent/enroll {enrollment_token, machine_id, machine_name, os, agent_version}
    S-->>D: {agent_id, tenant_id, agent_token}
    D->>S: GET /ws?role=agent&token=<agent_token>  (always-on control link)
```

`machine_id` is a stable hardware-derived hash, unique per `(tenant_id, machine_id)`
— re-enrolling a known machine reuses its row. The tunnel-client flow is identical
in shape (`…/tunnel-client/enroll-token` → `POST /api/tunnel-client/enroll` →
`{tunnel_client_token}`), with a distinct audience so a leaked agent token can't
impersonate a client or vice-versa.

### Rate limiting

Everything under `/api` sits behind a per-client-IP governor (trusted-proxy-aware —
it will not believe a client-supplied `X-Forwarded-For`). `POST /api/auth/login` and
`/register` carry an additional per-(IP, account) brute-force gate. `/health`,
`/ws`, `/derp`, and the Stripe webhook are deliberately outside the governor.

## Public routes (no user JWT)

Auth, where present, is in-handler (enrollment tokens, agent/tunnel bearer tokens,
capability URLs, webhook signatures).

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/auth/register` | Create account (+ optionally a tenant, or accept `invite_code`) |
| POST | `/api/auth/login` | Password login (`email` or `username`) |
| POST | `/api/auth/logout` | Invalidate session |
| POST | `/api/auth/refresh` | Rotate the access token |
| POST | `/api/auth/activate` | Redeem an email activation code |
| GET/PUT | `/api/auth/me` | Current user (read / update) |
| GET | `/api/oauth/{provider}` | OAuth redirect (google, facebook, github, linkedin, microsoft) |
| GET | `/api/oauth/callback/{provider}` | OAuth callback |
| GET | `/api/invite/{code}` | Public invite info |
| POST | `/api/invite/{code}/accept` | Accept an invite (authed) |
| GET | `/api/stripe/plans` | Plan catalogue |
| POST | `/api/stripe/checkout` · `/portal` | Stripe checkout / customer portal |
| POST | `/api/stripe/webhook` | Stripe events (HMAC-signed; un-governed). FR-102 P4: the six billing kinds (`customer.subscription.{created,updated,deleted,trial_will_end}`, `invoice.paid`, `invoice.payment_failed`) are also recorded in `billing_events` with the invoice's amounts ([growth-observability.md](growth-observability.md#revenue-what-stripe-billed-p4)) |
| POST | `/api/sendgrid/webhook` | FR-102 P5 (`saas`): SendGrid's Event Webhook — ECDSA P-256 signed, verified **before the body is parsed** (401), the empty 404 without `ROOMLER__NEWSLETTER__EVENT_WEBHOOK_PUBLIC_KEY`; records `delivered` · `bounce` · `dropped` · `spamreport` of newsletter messages on their ledger rows (never opens or clicks); un-governed ([growth-observability.md](growth-observability.md#the-newsletter-delivery-per-issue-tags-and-unsubscribes-p5)) |
| POST | `/api/agent/enroll` | Exchange enrollment token → agent credential |
| GET | `/api/agent/latest-release` | Agent release manifest (cached GitHub proxy) |
| GET | `/api/agent/installer/{flavour}` (+`/health`) | Stream the MSI/installer through roomler.ai (`peruser` \| `permachine`) |
| POST | `/api/agent/crash` | Crash-report ingest (agent JWT in-handler) |
| POST | `/api/consent/{token}/approve` · `/deny` | Owner-consent capability URLs (token **is** the auth, single-use) |
| POST | `/api/tunnel-client/enroll` | Exchange tunnel enrollment token → client credential |
| GET | `/api/tunnel-client/agents` | Reachable agents (TunnelClient bearer) |
| GET | `/api/tunnel/latest-release` · `/installer/{platform}` (+`/health`) | Tunnel-CLI release manifest + artifact proxy |
| GET | `/api/setup/latest-release` · `/{platform}` (+`/health`) | `roomler-setup` wizard manifest + artifact proxy |
| GET | `/api/setup/install.sh` · `/install.ps1` | Terminal installers (served from the binary, curl-able) |
| POST | `/api/setup/diagnostics` | FR-102 P3b: the setup wizard's **opt-in** step diagnostics — one `{run, step, outcome, elapsed_ms, error_code, os, wizard_version}` per step boundary, sent only when the person ticked the box. Unauthenticated by necessity, so every field is checked against its vocabulary (422 with a code, nothing stored); body ≤ 1 KiB; ≤ 48 rows per run (429 `run_capped`); 202 with no body. Stores no IP and no User-Agent. The empty 404 while `ROOMLER__GROWTH__SETUP_DIAGNOSTICS=false` ([growth-observability.md](growth-observability.md#the-wizards-opt-in-diagnostics-p3b)). The static segment also makes `GET /api/setup/diagnostics` a 405 (it used to fall into the `{platform}` proxy's 400) |
| POST | `/api/releases/refresh` | CI cache-bust after a release is published (bearer; fans out to all pods) |
| GET | `/api/turn/credentials` | Ephemeral TURN credentials (user-scoped) |
| GET | `/api/relay/regions` | Multi-region relay PoP topology (read-only) |
| POST | `/api/log/browser` | Browser console-log batch ingest (user JWT + explicit `tenant_id`) |
| GET | `/api/cluster/status` | Per-pod identity, counters, gauges |
| POST | `/api/stats/pageview` | SPA route-change beacon (authed, paths normalized) |
| GET | `/health` | Liveness — cheap process-alive 200 |
| GET | `/health/ready` | Readiness — Mongo ping + Redis round-trip + live subscription |

### User-scoped (access JWT, no tenant prefix)

| Method | Path | Purpose |
|---|---|---|
| PUT | `/api/user/me` | Update profile |
| GET | `/api/user/unread-summary` | Cross-tenant unread counters |
| GET | `/api/user/{user_id}` | Public profile |
| GET | `/api/giphy/search` · `/trending` | Giphy proxy |
| GET | `/api/push/config` | VAPID public key |
| POST | `/api/push/subscribe` · `/unsubscribe` | Web-push subscription |
| GET | `/api/notification` · `/unread` · `/unread-count` | Notification feeds |
| PUT | `/api/notification/{id}/read` | Mark one read |
| POST | `/api/notification/read-all` | Mark all read |
| GET/PUT | `/api/user/newsletter` | FR-58: the signed-in newsletter toggle — a door into the same `subscribers` store the public form writes; subscribing pre-confirms only on a verified account email |

### Device-scoped — `/api/agent/self/*` (agent JWT, no tenant prefix)

The device's own view of its org, for the desktop companion (FR-84 D5a). The
companion reaches only its local daemon, and the daemon holds an **agent** token,
so the admin grid and the org mesh above are out of its reach; these answer the
same questions **for one device**. Authentication is the agent's bearer token,
audience- and status-checked on every call (a user JWT, a quarantined or a deleted
device are each a 401); without the fleet module the answer is 503.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/agent/self/devices` | The devices this device may see, itself included — searched, sorted and paged on the server (`page`, `per_page`, `q`, `sort`, `dir`, `kind`, the admin grid's own contract; an unknown `sort` is a 400) |
| GET | `/api/agent/self/mesh` | The org mesh graph restricted to the same set, with a server-computed `label` per node and the caller's `self_node_id`; `{"enabled": false}` when stats are off |

**The visibility rule.** `visible = self ∪ what this device's overlay netmap
already carries`. The set is computed by the join path's own shaping
(`overlay::shape_full_netmap`, the function that builds the `rc:overlay.netmap` a
node receives), never by a second rule: under ACL `off` and `warn` every live node
is listed, under `enforce` exactly the peers the netmap would ship. A device
without a live overlay node lists itself alone (`overlay: "no_node"`; `"no_network"`
when the org has no mesh yet, `"unavailable"` without the network module), and the
GET never creates a network row. Rows carry `display_name`, `name`, `os`, `version`,
`presence`, `overlay_ip`, MagicDNS, `tags`, `reachable` and `is_self` — never
`machine_id`, owner ids, keys, consent settings or codecs; those fields are blanked
before the search runs, so `q` cannot probe them.

```json
{
  "items": [{ "kind": "agent", "id": "…", "name": "bravo-box", "display_name": "Kilo",
              "os": "linux", "version": "0.4.103", "presence": "online", "is_online": true,
              "last_seen_at": "2026-09-25T09:00:00Z", "overlay_ip": "100.64.0.3",
              "overlay_node_id": "…", "magic_dns_name": "bravo-box", "reachable": true,
              "is_self": false }],
  "total": 2, "page": 1, "per_page": 25, "total_pages": 1,
  "overlay": "ok", "acl_mode": "enforce", "self_node_id": "…"
}
```

### Public newsletter list (FR-39/FR-58 — no auth; see [newsletter.md](newsletter.md))

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/subscribe` | Always **202** (membership-oracle control); double-opt-in confirmation mail, 15-min per-address resend cooldown |
| GET | `/api/subscribe/confirm/{token}` | **Pure redirect** to the confirm page — never confirms (mailbox link scanners follow GETs; field-hit on day one) |
| POST | `/api/subscribe/confirm/{token}` | The deliberate click (the confirm page's button); single-use, answers `{confirmed: bool}` |
| GET | `/api/subscribe/unsubscribe/{token}` | Idempotent; 303 → `/newsletter/unsubscribed?status=…`; the token never expires. FR-102 P5: `?i=<slug>` (an issue's link, the same for every recipient) is recorded once as `subscribers.unsubscribed_via` |
| POST | `/api/subscribe/unsubscribe/{token}` | RFC 8058 one-click target — plain 200 for every outcome, body unread; `?i=` as the GET |

### Platform-admin (`platform_admins` ObjectId allowlist; 404 on miss)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/admin/stats/relay/current` · `/relay/history` | Relay (TURN/DERP) load, live + series |
| GET | `/api/admin/stats/orgs` · `/users` · `/machines` · `/calls` | Platform-wide inventories |
| GET | `/api/admin/stats/usage` · `/usage/{user_id}` | Per-user usage across every org |
| GET | `/api/admin/stats/attribution` | FR-88: sign-ups by campaign key and how many activated — counts only |
| GET/PUT | `/api/admin/growth/exclusions` | FR-102 P1c: the orgs and people no growth number counts — the implicit set (platform admins, the orgs they own) marked beside the explicit rows; PUT replaces the explicit list (`{kind: tenant\|user, id, reason}`). 404 also when `growth.enabled = false` |
| GET | `/api/admin/growth/digest?day=` · `/digests?since=&limit=` | FR-102 P1d: a stored daily digest (the latest when `day` is omitted; dates as RFC 3339 strings), and the list with each day's status and headline ([growth-observability.md](growth-observability.md)) |
| POST | `/api/admin/growth/digest/run?day=&send=false` | Recompute and overwrite a closed day's sections, through the same claim the scheduler uses (409 while a run of that day is in progress); `send=false` ends `preview`, which the scheduler still claims; mails only with `send=true` AND a day not already `sent` |
| GET | `/api/admin/growth/digest/preview?day=&include_internal=` | Compute a day live — stores nothing, mails nothing; `include_internal=true` is the raw totals with the exclusion set empty |
| GET | `/api/admin/growth/funnel?since&until&by&include_internal` · `/cohorts?unit=week&since` · `/orgs?limit&include_internal` · `/org/{tenant_id}/timeline` | FR-102 P2: the account funnel with `pending`/`settled` per step and time to value, the weekly cohorts with the WAO north star, the org table, one org's milestones |
| POST | `/api/admin/growth/org-daily/backfill?since&until` | FR-102 P2: recompute a closed range of `growth_org_daily`, clamped to its 25-month retention |
| GET | `/api/admin/growth/revenue?since=YYYY-MM&until=YYYY-MM&include_internal` | FR-102 P4: billed revenue from `billing_events` — billed MRR and paying orgs now per currency, new · expansion · contraction · churned MRR month by month (a closed month read frozen from `growth_daily`; a month before the first billing row `on_record: false`, never 0), trial → paid, by the owner's channel; beside the list-price ESTIMATE, the 30-day cost to serve and margin per org, and the range's plan-limit collisions. `billed` is `not_measured` without `saas` or with nothing on record ([growth-observability.md](growth-observability.md#revenue-what-stripe-billed-p4)) |
| POST | `/api/admin/growth/billing/backfill?since=YYYY-MM-DD` | FR-102 P4 (`saas`): the operator's one-off read of Stripe's paid invoices into `billing_events` (idempotent; reads Stripe, never writes), then a refreeze of the closed months they touch; answers the counts (`invoices`, `recorded`, `already`, `no_org`, `truncated`) and the months. 400 without `ROOMLER__STRIPE__SECRET_KEY` |
| GET | `/api/admin/growth/channels?since&until&include_internal` | FR-102 P8: per platform and per post published in the range — the platform's own reach (raw metric names, summed per snapshot age), then visitors → sign-ups → activated by each post's normalised key, and spend (`cost_cents`, per visitor / per sign-up from n ≥ 30); a platform with nothing pushed reads `not_measured` |
| GET/POST | `/api/admin/growth/keys` | FR-102 P8 (D12): list the growth machine keys (prefix, label, use, revoked — never the key or its hash) / mint one `{kind: "ingest" \| "read", label}` — the key is in the 201 answer only, its SHA-256 is all that is stored; at most 10 live per kind. **Session only**: a read key meets the empty 404 here, GET included |
| DELETE | `/api/admin/growth/keys/{key_id}` | Revoke a key (204, idempotent) |
| GET | **every `/api/admin/growth/*` GET view** | FR-102 P10 (D12): besides the platform admin's session, a **read key** (`Authorization: Bearer rgr_…`) opens the GET data routes — the digests, funnel, cohorts, orgs, timeline, campaigns, channels, newsletter, revenue, weekly, alerts — and answers exactly what the session answers (AC20). Every non-GET, `/keys`, `/exclusions`, an ingest key, a malformed, unknown or revoked key and `growth.enabled = false` are the empty 404 of an absent path; a lookup failure is 503 ([growth-observability.md](growth-observability.md#the-read-key-d12)) |
| GET | `/api/admin/growth/weekly?week=` · `/weeklies?since=&limit=` | FR-102 P10: a stored weekly roll-up (`YYYY-Www`, the latest when omitted; the week's headline against the weeks before, and the funnel, cohorts, campaigns, channels, newsletter and alerts computed for that week), and the list with each week's status and headline |
| POST | `/api/admin/growth/weekly/run?week=&send=false` | Recompute a closed ISO week through the same claim the Monday scheduler uses (409 while a run of that week is in progress; 400 for an open week); `send=false` ends `preview`; mails only with `send=true` AND a week not already `sent` |
| GET | `/api/admin/growth/alerts?since=` | FR-102 P10: the open alert rows and the ones cleared since `since` (default 7 days) — rule, key, fired/cleared, the numbers behind it — plus the rule table; `enabled` says whether the hourly evaluator runs here |
| POST | `/api/admin/growth/alerts/evaluate?dry_run=` | Evaluate every rule now as the hourly job would (fire, clear, mail at most once per rule and key per day); 409 when `growth.alerts` is off unless `dry_run=true`, which decides and writes nothing |
| GET | `/api/admin/growth/quality?since&until&include_internal` | FR-102 P9a: remote-desktop quality over a closed range of days frozen nightly into `growth_quality_daily` (default the last 28; an open `until` is clamped to yesterday; at most 400 days) — `totals` (every version pooled: sessions requested → reached Active / never / pending with `by_end_reason`, duration · peak fps · RTT as pooled `{n, p50, p90, exact}`, FR-22's time to first frame with the records set aside, crashes, device-days, crashes per 100 device-days from n = 30), `by_agent_version` (newest first, `unknown` last), `series` (one row per frozen day), `frozen_days` of `days`; `not_measured` with the reason when nothing is frozen; `include_internal=true` reads the `all` scope ([growth-observability.md](growth-observability.md#remote-desktop-quality-from-what-is-recorded-p9a)) |
| POST | `/api/admin/growth/quality/backfill?since=YYYY-MM-DD&until=` | FR-102 P9a: re-freeze a closed range, both scopes, with the current exclusion set — clamped to 730 days back, never today (400 otherwise); time to first frame comes back only for the days whose `agent_logs` are still complete |
| POST | `/api/tenant/{tenant_id}/session/{session_id}/feedback` | FR-102 P9b (`remote`): the viewer's post-session rating `{rating: up \| down, reasons: [lag \| picture \| input \| could_not_connect \| other]}` (≤ 1 KiB, `deny_unknown_fields`), from the session's controller or a watcher, resolved within the org — 201 with what was stored; 403 `not_a_member` / `forbidden`; 404 for a session the org does not own; 409 `too_early` (sooner than 30 s after the request) / `already_rated` (one per session **per person** — the unique `(session_id, user_id)` index decides; the controller and each watcher rate once each); 422 `invalid_json` / `unknown_rating` / `unknown_reason` / `too_many_reasons` with a code and nothing stored; 413 over the limit; the **empty 404** of an absent path while `ROOMLER__GROWTH__FEEDBACK=false`. `GET /api/capabilities` → `features.session_feedback` says whether a viewer may offer the prompt ([growth-observability.md](growth-observability.md#the-post-session-rating-p9b)) |
| POST | `/api/admin/growth/ingest/posts` · `/ingest/snapshots` | FR-102 P8, **`saas` only, authenticated by an ingest key** (`Authorization: Bearer rgi_…`), not a user JWT: the promotion pipeline pushes a post `{platform, platform_id, account, format, url, published_at, utm_*, cost_cents?}` (idempotent on `(platform, platform_id)`) or a snapshot `{platform, platform_id, snapshot: T+1d\|T+7d\|T+28d, taken_at, metrics}` (stored once). A missing, wrong or revoked key is the empty 404 of an absent path; unknown platforms and any field that looks like post text are `422` ([growth-observability.md](growth-observability.md)) |
| GET | `/api/admin/growth/newsletter?since&until&include_internal` | FR-102 P5: the list over time (new · confirmed · unsubscribed · suppressed per day and by source, the size now) and one row per issue sent in the range — recipients and accepted from the ledger, delivered · bounced · complaints from SendGrid's signed events, unsubscribed through the issue's link, purestat visits and sign-ups by the issue's campaign key; delivery `not_measured` without the webhook key, never 0 ([growth-observability.md](growth-observability.md#the-newsletter-delivery-per-issue-tags-and-unsubscribes-p5)) |
| GET | `/api/admin/growth/campaigns?since&until&by&include_internal` | FR-102 P6: per normalised campaign key (`by` = `source`·`medium`·`campaign`·`content`), purestat's web plane queried **live** for the exact UTC-day range beside the account funnel; a purestat outage or revoked key reads `not_measured`, never 0; every rate `{n, value}` with a value only at n ≥ 30 ([growth-observability.md](growth-observability.md)) |
| POST | `/api/admin/overlay-block/reclaim` | Reclaim quarantined overlay address blocks (dry-run by default) |
| POST/GET | `/api/admin/newsletter/issues` | FR-58: create draft / list issues |
| PUT/GET | `/api/admin/newsletter/issues/{slug}` | Edit while draft (409 after) / read back |
| GET | `/api/admin/newsletter/issues/{slug}/preview` | The exact send-path bytes (sample unsubscribe link substituted) |
| POST | `/api/admin/newsletter/issues/{slug}/test-send` | Render + send to one address, real headers, honest failures |
| POST | `/api/admin/newsletter/issues/{slug}/send` | Claim + fan out; re-POST = resume; `{"retry_stale":true}` re-attempts stuck rows |
| GET | `/api/admin/newsletter/issues/{slug}/status` | Live ledger counts while sending; stored snapshot once completed |

## Tenant-scoped routes — `/api/tenant/{tenant_id}/…`

Caller must be a member of the tenant; write operations check the caller's role
permissions (24-bit bitfield — see [use-cases.md](use-cases.md#permission-system)).

### Organization

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/api/tenant` | List my tenants / create one |
| GET | `/api/tenant/{tid}` | Tenant detail |
| POST | `…/archive` · `…/unarchive` | Owner-only; archiving revokes every device enrollment and releases the mesh |
| GET | `…/member` · POST `…/member` | List / add members |
| GET | `…/member/me` | My membership + permissions |
| GET/POST | `…/role` | List / create roles |
| PUT/DELETE | `…/role/{role_id}` | Update / delete a role |
| POST/DELETE | `…/role/{role_id}/assign/{user_id}` | Assign / unassign |
| GET/POST | `…/invite` | List / create invites |
| POST | `…/invite/batch` | Batch email invites |
| DELETE | `…/invite/{invite_id}` | Revoke |
| GET | `…/search?q=` | Full-text search: messages, rooms, people |

### Rooms, chat, calls

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `…/room` | List / create rooms (hierarchical: `parent_id`, `path`) |
| GET | `…/room/explore` | Discoverable rooms |
| GET/PUT/DELETE | `…/room/{rid}` | Room CRUD |
| POST | `…/room/{rid}/join` · `/leave` | Membership |
| GET | `…/room/{rid}/member` | Room members |
| POST | `…/room/{rid}/call/start` · `/join` · `/leave` · `/end` | Call lifecycle (mediasoup) |
| GET | `…/room/{rid}/call/participant` | Live participants |
| GET/POST | `…/room/{rid}/message` | Paginated history / send |
| GET | `…/message/pin` | Pinned messages |
| PUT/DELETE | `…/message/{mid}` | Edit / delete |
| PUT | `…/message/{mid}/pin` | Toggle pin |
| GET | `…/message/{mid}/thread` | Thread replies |
| POST | `…/message/{mid}/reaction` | Add reaction |
| DELETE | `…/message/{mid}/reaction/{emoji}` | Remove reaction |
| POST | `…/message/read` · `/read-all` | Read markers |
| GET | `…/message/unread-count` | Unread count |
| GET/POST | `…/room/{rid}/recording` | List / create recordings |
| DELETE | `…/recording/{rec_id}` | Delete recording |

A room or message response may carry `binding {module, ref}` — another module owns what it
means (FR-90: an agent session's room, and the turn stubs in it). Chat stores it and never
interprets it. A message also carries `author_type` (`user` · `bot` · `webhook` · `system`).
An agent's message is authored by its **session**: `author_id` is the session's id and
`author_name` is `Claude · <device>`. The edit and delete routes match the author, so they
refuse every person, the session's owner included — a stub reads as the agent's, and only the
agent's session can change it.

### Files, tasks, export

| Method | Path | Purpose |
|---|---|---|
| GET | `…/room/{rid}/file` · POST `…/file/upload` | Room-scoped files (100 MB limit) |
| GET/POST | `…/file` · `…/file/upload` | Tenant file library |
| GET | `…/file/{fid}` · `/download` | Metadata / streamed download |
| DELETE | `…/file/{fid}` | Delete |
| POST | `…/file/{fid}/recognize` | AI document recognition (Claude vision) |
| GET | `…/task` · `…/task/{tid}` · `/download` | Background tasks + results |
| POST | `…/export/conversation` | XLSX export |
| POST | `…/export/conversation-pdf` | PDF export |

### Fleet — agents & remote sessions

| Method | Path | Purpose |
|---|---|---|
| GET | `…/agent` | List enrolled devices (status, caps, overlay info) |
| POST | `…/agent/enroll-token` | Mint an enrollment token (10 min, single-use) |
| POST | `…/agent/update` · `…/agent/{aid}/update` | Operator-forced self-update (fleet / one device), `{pin?, force?}` (+ `agent_ids?` for the fleet). A push that would not be acted on is refused, never sent: FR-2's downgrade guard (`pin_downgrade`, unless `force`), and since FR-67 P7 a device whose caps say it ignores the push (`primary_org`, a secondary enrollment) or drops it (`auto_update_off`). `force` lifts only the first. One device answers **409** with the reason; the fleet route skips the device with a `refused` reason and its `refused_code`, and counts it in `refused` |
| POST | `…/agent/{aid}/join-org` · GET `…/join-targets` | Add an enrolled device to a second org (multi-org) |
| GET/PUT/DELETE | `…/agent/{aid}` | Device detail / settings / remove (cascades: revoke + mesh release). Removal is final: from then on the device is a **404 on every per-device route** — this GET and PUT, the policies, `desired-config`, `update`, `exec`, `ssh`, `join-org` — and a repeat DELETE is a 404 too, like the listing that no longer shows it. Only the audit views (`…/recording-activity/{aid}`, `…/transfer-activity/{aid}`) still resolve a removed device |
| GET | `…/agent/{aid}/crash` | Crash reports |
| POST/GET | `…/agent/{aid}/logs` | Log batch ingest (agent JWT) / admin listing |
| POST | `…/agent/exec` · `…/agent/{aid}/exec` | Fleet RPC: run a command (fleet sweep / one device) — see [fleet-rpc.md](fleet-rpc.md) |
| POST | `…/agent/{aid}/exec/{request_id}/cancel` | Cancel a running exec |
| PUT | `…/agent/{aid}/exec-policy` | Per-device exec gate (a management act, separate from the exec power) |
| POST | `…/agent/{aid}/overlay-key/rotate` | Order the device to retire its overlay (WireGuard) key — it mints locally, re-joins and reports back; the server never sees a private key (FR-40). `MANAGE_AGENTS`, one order per device per minute. 200 `{request_id, dispatch: "pushed" \| "queued", delivered}`; 409 `rate_limited` / `agent_unsupported` (online device without the `key-rotate` verb) — see [overlay-key-rotation.md](overlay-key-rotation.md) |
| GET | `…/exec-audit` | Org-wide exec attempt log (every refusal included) |
| GET/PUT | `…/exec-settings` | Org exec kill-switch (gate 1 of 4) |
| GET/PUT | `…/keep-busy-settings` | The org's keep-busy policy (FR-92): `{keep_busy_denied, keep_busy_default_pattern}`. **GET: any member** (a viewer pre-selects the default). **PUT: `MANAGE_TENANT`**; each field optional, absent = unchanged, `keep_busy_default_pattern: null` = the product default (circle); a pattern not in the agent's exact wire list is a 400; a deny in the body is pushed to every device — see [keep-busy.md](keep-busy.md) §7, §12 |
| GET | `…/keep-busy-history` | The **permanent** keep-busy history (FR-92 P7), newest first: `?agent_id=<hex>&before=<RFC 3339 \| unix ms>&limit=<1..=200, default 50>`. `MANAGE_AGENTS`; always tenant-scoped (another org's device id answers with nothing). `source: server` rows are the server's own decisions, `device` rows the device's claims from its heartbeats — see [keep-busy.md](keep-busy.md) §11 |
| GET | `…/session/{sid}` | Remote-desktop session detail |
| POST | `…/session/{sid}/terminate` | Force-terminate |
| GET | `…/session/{sid}/audit` | Session audit trail |
| GET | `…/recording-activity/{aid}` | What a device reported about remote recordings (FR-85), newest first; `VIEW_REMOTE_AUDIT` — see [recording.md](recording.md) §10 |
| GET | `…/transfer-activity/{aid}` | The clipboard and file traffic a device reported for remote sessions (FR-101 P3): counts, bytes, and a SHA-256 of each file name. Never content, never a name. Newest first; `VIEW_REMOTE_AUDIT`. A removed device's trail still resolves — see [remote-control.md](remote-control.md) §11.3a |
| GET/POST | `…/touch-preset` | The org's on-screen control presets (FR-111 P4a, module `remote`), which every member's viewer offers beside the built-ins. GET for **any member**: `{items: [{id, name, controls, updated_at}]}` in name order. POST with `MANAGE_TENANT`: `{name, controls}` (≤ 32 KiB, `deny_unknown_fields` at every level) → 201 with the stored preset; 409 `name_taken` (unique per org) / `too_many_presets` (50); 422 with a code and nothing stored (`invalid_json`, `name_empty`, `key_invalid`, `macro_too_long`, … — `TouchPresetRequest::validate`); 413 over the limit. See [touch-controls.md](touch-controls.md#the-orgs-presets-p4) |
| PUT/DELETE | `…/touch-preset/{preset_id}` | Replace a preset's name and controls (200, the stored row; the same 409 and 422 as a create) or delete it (204). `MANAGE_TENANT`; the preset resolved **within** the org, so a foreign id is a 404 that leaks nothing |
| GET | `…/privacy-activity/{aid}` | What a device reported about privacy mode (FR-99 P1d): each curtain `on`, `off` with its reason (`controller`, `session_end`, `disabled_on_device`, `worker_exit`) and each `refused` "on". The device's claim, kept only for a session whose grant held `PRIVACY`. Newest first; `VIEW_REMOTE_AUDIT`. A removed device's trail still resolves — see [privacy-mode.md](privacy-mode.md#what-is-recorded) |

Exec body (`POST …/exec`): `{shell?: "pwsh"|"powershell"|"cmd"|"bash"|"sh", command,
timeout_ms?, max_output_bytes?}` — clamped server-side; output is secret-redacted
before it leaves the host.

### Tunnels

| Method | Path | Purpose |
|---|---|---|
| GET | `…/tunnel-client` | List enrolled tunnel clients |
| POST | `…/tunnel-client/enroll-token` | Mint a tunnel enrollment token |
| PUT/DELETE | `…/tunnel-client/{cid}` | Rename / relabel / re-tag a client · revoke it (releases its overlay node; a live session is kicked by the 60 s revocation sweep with `rc:tunnel.revoked`). Removal is final: from then on the client is a **404 on both routes** — PUT and a repeat DELETE — like the listing that no longer shows it. There is no GET by id; the listing is the only read |
| GET/POST | `…/tunnel-policy` | List / create ACL policies (default-deny) |
| GET/PUT/DELETE | `…/tunnel-policy/{pid}` | Policy CRUD. A deleted policy is a **404 on all three** (GET, PUT, repeat DELETE), exactly as it is absent from the listing and from the forward gate's compile set — it is never served, edited or compiled again |

### Overlay network

| Method | Path | Purpose |
|---|---|---|
| GET | `…/overlay-node` | Mesh nodes with advertised + approved routes |
| PUT | `…/overlay-node/{nid}/approved-routes` | `{approved_routes: ["10.0.0.0/24", …]}` — approve subnet-router routes (the data-plane signal) |
| PUT | `…/overlay-node/{nid}/exit-node` | `{enabled: bool}` — designate an exit node (also adds `/0` to approved routes) |
| DELETE | `…/overlay-node/{nid}` | Evict from the mesh + release the address back to the pool |
| GET/POST | `…/overlay-acl` | Overlay L3 ACL policies |
| GET/PUT | `…/overlay-acl/mode` | Tenant posture: `off` (default) \| `warn` \| `enforce` |
| GET/PUT | `…/server-link` | Server topology: `GET` lists the current servers (with the `country` and `zone` of each one's last observed connection, for the map) and links; `PUT {a, b, enabled}` (agent ids, `ADMINISTRATOR`) adds, enables or disables the link between two servers |
| DELETE | `…/server-link/{a}/{b}` | Remove a server link (`ADMINISTRATOR`) |
| GET/PUT/DELETE | `…/overlay-acl/{pid}` | ACL policy CRUD. A deleted policy is a **404 on all three** (GET, PUT, repeat DELETE), exactly as it is absent from the listing and from the netmap compiler's set — it is never served, edited (in particular never re-`enabled`) or compiled again, and a repeat DELETE re-fans nobody |
| GET/PUT | `…/magic-dns` | Tenant MagicDNS domain + upstream resolvers |
| GET | `…/overlay-block` | The tenant's overlay address block |
| POST | `…/overlay-block/renumber` | Migrate onto a disjoint block (**dry-run by default**; cycles agent connections) |

### Agent sessions (FR-90, module `hive` — mounted only with `[modules] hive = true` or a `hive.tenants` list)

FR-90 P1g — and only for the organizations in `hive.tenants` (`ROOMLER__HIVE__TENANTS`,
comma-separated ids; empty or `*` is every organization). A member of any other organization gets
**404** on every route below (`agent sessions are not available to this organization`), the viewer
answers `not_found`, and its devices are told to stop what they still run for it when they connect.
Membership is checked first, so someone outside an organization learns nothing about whether it is
served. A list mounts the module by itself, with no `[modules] hive` (P1g-2): the form a hosted
server uses, because no older image reads a list as the switch — promoting one leaves the module
off instead of open to every organization.

| Method | Path | Purpose |
|---|---|---|
| GET | `…/hive` | P1g — whether agent sessions serve this organization: `{enabled: true}`, or **404** where they do not. The SPA asks before it shows any of the module's pages |
| POST | `…/hive/session` | `{device_id, folder, title?, role?}` — start an agent session on a device; `role` (FR-90 P3-2b) is a vault role the vault must allow the starter on that device first ([vault.md](vault.md) §8). Always **200** for a well-formed request: `outcome` is `accepted` (the device is launching it), `refused` (`reason` names the gate — the server's `org_archived` · `no_permission` · `device_offline` · `device_unsupported` · `rate_limited` · `role_refused` · `vault_unavailable` · `role_undecided`, or the device's `hive_disabled` · `no_account` · `no_console_user` · `folder_not_allowed` · `harness_missing` · `launch_failed` · `at_capacity`) or `pending` (no answer within 10 s; the session updates when it comes). Needs `HIVE_RUN`; every attempt is in `hive_audit`, and with `hive.replicaset` on so is the session's placement (`action: place`, `placed` or `short`) |
| GET | `…/hive/session` | The caller's own sessions, newest first (paginated) |
| GET | `…/hive/session/{sid}` | One session, for anyone who may read it: its owner and the members of its room (P1c). Anyone else's read is a **404**, the answer a bogus id gets. `drivers` lists who besides the owner drives it. `origin` is `started` or, for a terminal session its owner adopted (P1j), `adopted`. `replicaset` (P2c-2b) is where its copies go, chosen when it started with `hive.replicaset` on, or when its primary first connected with it on (P2c-4b): `{policy_revision, min, max, restricted_tags, members[{device_id, role, state, refusal?, answered_at?, tip?}], short?, placed_at}`, `role` being `primary`, `archive`, `owner` or (P2f-1, a teleport's target) `teleport`, and `short` (`restricted` · `no_device`) present when it holds fewer than `min`. Each member's `state` (P2c-3a) is `pending`, `joined`, `refused` (`refusal` says which of the device's gates) or, once placement no longer chooses it (P2c-4a), `leaving`. The primary is `joined` from its placement, and `pending` while it is owed its join (P2c-4b: its session gained its first member after a start that said it had none), then `joined` or `refused` by its own answer. `tip` is where its copy ends as it last said: `{fence, seq, hash, checkpoint_seq?, checkpoint_hash?, at}`, and `holds` (P2j-1) is how much of the session's chain that copy holds, as a `seq`, counted by the rule a promotion is decided by: a tail past where its fence ended counts for nothing, so the freshest copy holds the most; absent without a `tip`. Absent for a session placed nowhere |
| POST | `…/hive/session/{sid}/stop` | Stop it — the owner only: `stopping` (the device was told), `queued` (it is not connected; told when it connects) or `ended`. Needs no permission — ending your own session is never what a role change blocks |
| POST | `…/hive/session/{sid}/promote` | FR-90 P2e-3 — `{device_id, folder?}` — the owner, holding `HIVE_RUN`, moves the session to a member of its replicaset that took its copy. Always **200** for a well-formed request: `outcome` is `promoting` (the member is ready; the primary drains), `refused` (`reason` names the gate: the server's `org_archived` · `no_permission` · `session_not_running` · `promotion_in_progress` · `moved_too_often` · `not_a_member` · `not_freshest` · `already_primary` · `device_offline` · `device_unsupported` · `primary_offline` · `primary_unsupported` · `rate_limited` · `role_refused` · `vault_unavailable` · `role_undecided` (P3-2b: a session with a vault role moves with it only as the vault allows it on the target), or the member's own start refusals) or `pending` (no answer within 10 s). The session's `promotion` (`{id, to, to_name, folder, from, from_fence, by, state, started_at, deadline, teleport?}`, `state` being `preparing` · `joining` · `draining` · `syncing` · `moving`) and its room say how it goes on. **404** with `hive.replicaset` off; every attempt is in `hive_audit` (`action: promote`) |
| POST | `…/hive/session/{sid}/teleport` | FR-90 P2f-1 — `{device_id, folder?}` — the same, to a device that holds no copy of the session: it prepares without one, takes a copy in a `joining` step while the session still runs, then the drain, the sync and the move are a promotion's. `outcome` is `teleporting`, `refused` or `pending`. The refusals are the promotion's, with `already_a_member` (the device holds a copy: promote to it) in place of `not_a_member`; the primary must be online (`primary_offline`: a teleport copies from it), and both ends must advertise `hive-teleport`. Audited as `action: teleport` |
| POST | `…/hive/session/{sid}/fork` | FR-90 P2f-3 — `{device_id, folder, title?}` — the owner, holding `HIVE_RUN`, makes a new session from this one's conversation, on a device that holds a copy of it (its primary, or a member that took its copy) or, from P2f-3c, on one that takes a copy first. The fork is a record of its own, its owner's, with its own room and replicaset under the session's restricted tags, naming the session in `parent_session_id`. The answer is a start's (`accepted` · `refused` · `pending`), or `joining` while a device with no copy takes one. The server's refusals: `org_archived` · `no_permission` · `not_forkable` (an adopted session) · `not_replicated` · `no_conversation` · `in_progress` · `no_copy` · `same_folder` · `restricted` · `copy_behind` · `device_offline` · `device_unsupported` · `primary_offline` · `primary_unsupported` · `rate_limited` · `role_refused` · `vault_unavailable` · `role_undecided` (P3-2b: the parent's vault role, decided again for the fork's device). **404** with `hive.replicaset` off, and for anyone but the owner. Audited as `action: fork`, naming the session it forks |
| POST | `…/hive/session/{sid}/manage` | FR-90 P2f-4 — `{folder?}` — the owner, holding `HIVE_RUN`, makes their ended adopted session (P1j) a managed one: the SAME record, at its fence, on the device that adopted it, which resumes the terminal's own history (P2f-4a). `folder` defaults to the terminal's. The answer is a start's: `accepted`, `refused` (the server's `org_archived` · `no_permission` · `in_progress` · `not_adopted` · `not_ended` · `stopped` (its mirroring was stopped from Roomler) · `ended_otherwise` · `device_offline` · `device_unsupported` · `rate_limited`, or the device's own start refusals) or `pending`. A start the device refuses, or that never reaches it, leaves the adopted session it was, the word kept as `from_terminal.refused`. The session's `from_terminal` (`{at, refused?}`) says it began in a terminal. **404** with `hive.replicaset` off, and for anyone but the owner. Audited as `action: manage` |
| DELETE | `…/hive/session/{sid}` | FR-90 P2g-2 — the owner, holding `HIVE_RUN`, purges the session from every device that held it (where it runs, its replicaset's members, where it ran before). The record becomes the purge's tombstone at once, read by nobody, the owner included; its room, core memory snapshot and approvals are deleted. Each device is sent `rc:hive.purge` while it is connected, and first at its next connection, until it answers. Always **200** for a well-formed request: `outcome` is `purging`, `purged` (every device answered, or none could be asked) or `refused` (`reason`: `no_permission` · `in_progress`, a promotion in flight); `purge` is `{id, session_id, reason, at, done_at?, devices[{device_id, state, store?, account?, detail?, answered_at?, closed?}]}`, `state` being `pending` · `done` · `closed` (`closed`: `device_removed` · `holds_nothing`), `detail` `device_unsupported` for a device whose agent does not purge yet; `forks` counts the sessions forked from it, which keep its conversation up to their fork. Asking again answers with the same purge. **404** with `hive.replicaset` off, and for anyone but the owner. Audited as `action: purge` (`issued`, `refused`, `complete`) |
| GET | `…/hive/session/{sid}/purge` | FR-90 P2g-2 — the owner's read of the purge of their session: the `purge` above, while it is pending and for 90 days after it completed. Its `reason` is `owner`, or (P2g-3a) `retention` for one the server's sweep issued once the session had been over for longer than the organization's `retention_days`. **404** for anyone else, for a session never purged, and with `hive.replicaset` off |
| GET | `…/hive/session/{sid}/participant` | FR-90 P1c — who takes part: `items[{user_id, display_name, role}]`, `role` `owner` · `driver` · `reader`, and `may_manage` (the owner alone). For anyone who may read the session |
| PUT | `…/hive/session/{sid}/participant/{user_id}` | `{role: "driver" \| "reader"}` — the owner names an org member: into the session's room, prompting it or not. A driver needs `HIVE_RUN` (**403** otherwise, audited `no_permission`), at most 16 besides the owner (**409**). The person's open views end `role_changed`, and the room is told. The owner's own id is a **400**. An adopted session (P1j) takes readers only: a driver is a **409**, because the terminal holds the harness |
| DELETE | `…/hive/session/{sid}/participant/{user_id}` | The owner takes someone out: out of the room, driving nothing, their views ended (`removed`). Idempotent |
| GET | `…/hive/brain?device_id=` | FR-90 P1e — core memory the caller may read: the org's facts, their own, and with `device_id` that device's (a live device of this org; 404 otherwise). `{brain_rev, facts[{id, scope, owner_id?, text, kind, version, created_by, created_at, updated_by, updated_at}], budgets[{scope, owner_id?, used, budget}]}` |
| POST | `…/hive/brain` | `{scope: "org" \| "user" \| "device", owner_id?, text, kind?}` — keep a fact: one line, at most 500 characters, `kind` one of `preference` · `convention` (the default) · `path` · `gotcha` · `decision` · `warning`. Org needs `ADMINISTRATOR`; user is the caller's own (`owner_id` defaults to them), with `HIVE_RUN`; device names a live device of this org, with `MANAGE_AGENTS` (**403** otherwise). A fact that does not fit its scope's budget (org 3,000, user 1,500, device 800 characters) is **409** `{error: "over_budget", message, scope, used, budget, needed}`; nothing is evicted |
| PUT | `…/hive/brain/{fact_id}` | `{text, kind?, version}` — change a fact at the version read: **409** `conflict` when it changed or was archived since, **409** `over_budget` when it grows past the budget. Someone else's user fact is a **404** |
| DELETE | `…/hive/brain/{fact_id}` | Archive a fact: out of every future snapshot and out of its budget, kept as a record. `{archived}` — `false` when it was not active |
| GET | `…/hive/policy` | FR-90 P2c-2a — where the organization's sessions are copied, for any member: `{replicaset: {min, max, archive, prefer[], restricted_tags[]}, retention_days, archive_devices[], revision, is_default, updated_by?, updated_at?}`. Until an administrator writes one, decision 2's defaults (`is_default: true`, `revision: 0`). **404** while the server's `hive.replicaset` is off |
| PUT | `…/hive/policy` | `{replicaset, retention_days, archive_devices[], revision}` — an `ADMINISTRATOR` sets it from the `revision` they read (**403** otherwise): `min` 1–8, `max` `min`–8, `prefer` only `owner_devices`, `restricted_tags` normalized as device tags are, `retention_days` 0–3650 (0 keeps sessions for ever), at most 16 archive devices, each a live device of this organization and not ephemeral (**400** otherwise). A write from a revision no longer stored is **409**. Every attempt is audited (`hive_audit`, `action: policy`), and a stored one places the organization's live sessions again (P2c-4a). **404** while `hive.replicaset` is off |

Metadata only, in both directions: no route here takes or returns a prompt, a tool call or an
output — see [the design](roomler-hive-design.md) §3.3. Core memory is the one exception by design:
curated facts, never a session's content. Every write is audited (`hive_audit`, `action: brain`),
and every write bumps the org's `brain_rev`. A session pins it when it starts and gets a frozen
snapshot of it (`rc:hive.memory`, sent just before `rc:hive.start` to a device that advertises
`hive-memory`).

**Reading a session (P0d-2) is not a route.** A member of the session's room sends
`hive:view.open {session_id}` on the user WebSocket ([real-time.md](real-time.md)). The server
checks org and room membership (anyone else gets `not_found`), the device (online, advertising
`hive-view`) and a rate (20 opens per minute per user and session). It then mints a grant, and
answers `hive:view.ready` with ICE servers only once the device has confirmed it. Refusals name
who said no: the server's `not_found` · `device_offline` · `device_unsupported` ·
`too_many_views` · `rate_limited` · `no_answer`, or the device's `hive_disabled` · `no_session` ·
`at_capacity`. The transcript itself flows browser ⇄ device over the peer and never through the
server. The starter of a live session may prompt it; everyone else reads. Every open is in
`hive_audit` (`action: view`).

**Searching (P2i-2) is not a route either.** A member sends `hive:search.open {tenant_id}` on the
user WebSocket. The server checks the organization (copies on, served, the asker a member; anyone
else gets `not_found`), then the policy's designated archive replicas online here that advertise
`hive-search` (none: `no_archive_replica`), one connection's grants and a rate (20 opens per minute
per user and organization). It names the sessions the asker may read whose copy the archive
replica holds, at most 500, the most recently active first (none: `no_session`), and answers
`hive:search.ready` with ICE servers and how many sessions it named once the device has confirmed
the grant. The rest of the handshake is a view's, by its grant. The query and every hit flow
browser ⇄ device over the peer and never through the server. Every open is in `hive_audit`
(`action: search`, with the count, never a query). `GET …/hive` answers `search`: whether the
organization can be searched, for the SPA's box.

**Adopted sessions (P1j) are not started by a route either.** A person adopts the Claude Code
sessions they run in a terminal (`roomler hive adopt`, on a device whose owner allows it:
`hive_adopt`, advertised as `hive-adopt`). The device offers each one with `rc:hive.adopt
{adopt_id, harness_session, keys, account, folder}`. The answer is `rc:hive.adopt_ack {adopt_id,
session_id, fence}`, or `{adopt_id, refused}`: `hive_not_enabled` · `rate_limited` · `no_account`
· `ambiguous_account` · `not_a_member` · `at_capacity`. The keys are the device's `hive_accounts` keys
for that account. The server adopts only when they name exactly one person, a member of the org:
an account two people share is refused, never attributed by guess. The record reads like any
session's, with `origin: "adopted"`. It is its owner's alone, readers by name, no drivers. It is
named after its folder, because a terminal's first prompt is content. An offer for a terminal
session already held is answered with the same record. Every adoption is in `hive_audit`
(`action: adopt`).

### Vault (FR-90 P3-1, module `vault` — mounted only with `[modules] vault = true` or a `vault.tenants` list)

The org gate reads like Hive's: `vault.tenants` (`ROOMLER__VAULT__TENANTS`) names the organizations
served, a list mounts the module by itself, and a member of any other organization gets **404**
(`the vault is not available to this organization`) after the membership check. Every route is
for the organization's `ADMINISTRATOR`s (**403** otherwise), and **no route answers a value**.
The vault lends to a served organization's PEOPLE (`roomler connect`, P3-9-1) only where
`vault.people` (`ROOMLER__VAULT__PEOPLE`) lists it, opt-in and empty by default.
Every `secret:*` and `vault:verify` decision is recorded in `vault_audit`, allow and deny; an allow
is written before it is acted on. Full treatment: [vault.md](vault.md).

| Method | Path | Purpose |
|---|---|---|
| GET | `…/vault` | `{enabled, kek: {state: ready · missing · invalid, recipient? \| reason?}, secrets, versions, other_kek}` — `other_kek` counts the versions wrapped to another KEK than the one loaded |
| GET | `…/vault/secret` | The live secrets, by path (`?prefix=` a folder). Metadata only, each with its `rrn` (`rrn:{org slug}:secret:{path}`) and the fields that hold a value |
| POST | `…/vault/secret` | `{path, kind: static · structured, description?, audiences?, exec_allow?, tags?, rotation_days?, disabled?, owner_id?}` — **201**; **409** when a live secret holds the path; **422** for an unknown field, `value` included |
| GET | `…/vault/secret/{id}` | One secret and `versions[]` — `{field, n, current, kek, created_by, created_at, expires_at}`, never the sealed bytes |
| PATCH | `…/vault/secret/{id}` | Its rules; `path` and `kind` never change (**422**). `rotation_days: 0` clears it |
| DELETE | `…/vault/secret/{id}` | Tombstone it and destroy every version: `{deleted: true, versions_destroyed}` |
| PUT | `…/vault/secret/{id}/value` | `{field?, value, expires_at?}` — the field's next version, sealed: `{field, n, created_at, expires_at}`. **503** without a usable KEK |
| POST | `…/vault/verify` | Open every version (up to 10,000): `{versions, ok, failed, failures[{secret_id, field, n, reason: other_kek · dek_unreadable · tampered}], truncated}`. **503** without a usable KEK |
| GET | `…/vault/audit` | The decisions, newest first (`?before=` RFC 3339, `?limit=` 1–200) |
| GET | `…/vault/activity` | P3-4d — what devices **report** doing with their leases, newest first (`?session_id=`, `?lease_id=`, `?before=` RFC 3339, `?limit=` 1–200): `{id, at, device_id, session_id, fence, kind: exec · render, lease_ids, target, exit_code, timed_out}`. Claims, never decisions; an empty answer is not evidence of disuse |
| GET | `…/vault/approval/{approval_id}` | P3-4e — an approval card as its session's readers see it: `{id, session_id, device_id, secret_id, rrn, field, mode, audience, ttl_s, status, requested_at, expires_at, answered_by, answered_at, lease_id, used_at, may_answer, may_approve}` (`may_approve`: the caller drives it now and the policy would take their yes); one past its deadline answers `expired`, one whose session moved or ended `withdrawn`. 404 for a caller who does not read the session, as for an id that names nothing |
| POST | `…/vault/approval/{approval_id}` | P3-4e — a driver's answer, `{answer: "approve" \| "deny"}`; a yes is decided by Cedar with the caller as the approver first. 403 for a caller who does not drive the session now, or whose yes the policy does not accept; 409 once it is answered, used, expired or withdrawn ([vault.md](vault.md) §18) |
| GET | `…/vault/schema` | P3-2a — `{schema, actions, modes, oses, secret_prefix}`: what a policy is written against |
| GET · POST | `…/vault/role` | P3-2a — the vault roles; `{name, description?}` declares one (**409** when a live role holds the name) |
| DELETE | `…/vault/role/{name}` | P3-2a — tombstone a role; **409** naming the live policies that still name it |
| GET · POST | `…/vault/policy` | P3-2a — the guardrails, then the organization's policies (`{id, name, description, text, effect, guardrail, rev, …}`); `{name, description?, text}` adds one, checked first (**400** in words) |
| GET · PUT · DELETE | `…/vault/policy/{id}` | P3-2a — one policy; `PUT {name, description?, text, rev}` replaces it from the revision read (**409** if it moved); a `guardrail:*` id is **400** for `PUT` and `DELETE` |
| POST | `…/vault/simulate` | P3-2a — `{action: role:assume · secret:use, principal, resource, device: {os, tags, owner_id}, mode?, audience?, ttl_s?, approver_id?, with?, without?}` → `{decision, determining[{id, name, guardrail}], errors}`. Decides nothing for real; records nothing. Also `secret:list`, `net:socks`, `net:forward` and `ssh:run`, and (P3-9-1) `secret:connect`: `principal.user_id` must be the device's `owner_id`, with no `mode` ([vault.md](vault.md) §7) |
| POST | `…/vault/simulate/replay` | P3-2b — `{with?, without?, days?}` (1–7, default 7): the recorded Cedar decisions of those days, each decided again from the request it recorded → `{days, replayed, unreadable, flipped, flips[{at, action, op, user_id, target, session_id, device_id, was, now, determining}], truncated}`. Decides nothing for real; records nothing |

### Observability

| Method | Path | Purpose |
|---|---|---|
| GET | `…/stats/overview` | Tenant overview (member-visible) |
| GET | `…/stats/mesh` | Mesh graph edges + carrier types |
| GET | `…/stats/machines` · `/calls` · `/tunnels` | Per-domain series (MANAGE_AGENTS) |
| GET | `…/stats/usage` · `/usage/{user_id}` | Usage (own row self-service; others need MANAGE_AGENTS) |

## Non-HTTP surfaces

| Surface | Where documented |
|---|---|
| `/ws` — user, agent, and tunnel-client roles; chat/presence/media signalling + the whole `rc:*` protocol | [real-time.md](real-time.md) |
| `/derp` — pubkey-addressed relay for UDP-blocked overlay pairs | [real-time.md](real-time.md#derp) |
| LocalAPI — on-host named pipe / unix socket used by `roomler`, `roomler-desktop` | [tunnels.md](tunnels.md#localapi) |
