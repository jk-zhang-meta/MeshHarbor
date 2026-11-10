# Plans and limits — what each plan allows, and where the code holds the line

**Status:** shipped in [FR-115](fr/FR-115-pricing-reshape.md) (#2557): the ladder and per-seat
billing (P1+P2), the concurrent-session cap (P3, counted cluster-wide by P3b since
2026-10-21), and the meeting cap (P5). The relay allowance on DERP (P4a) has been on since
2026-10-21; its TURN half is not built yet. Claims were checked against the code at `8ab970586`.

The price list and the reasoning behind it are in [business-model.md](business-model.md) §4.
This page is the engineering view: where the numbers live, the one place they are compared,
which limits can be softened and which cannot, and the switches that turn each off.

## 1. Where the numbers live

One function holds the matrix: `Plan::limits_for(seats)` (`crates/db/src/models/tenant.rs:554`). Fields priced
per seat (concurrent sessions on Pro, relay, storage) are multiplied by the org's billed
seats, `Tenant::billed_seats` (`crates/db/src/models/tenant.rs:466`): one on Free, the subscription's quantity
on a paid plan, never below one. A paid org whose webhook has not landed yet is computed at
one seat, so a missing number can only under-grant.

| Limit (`PlanLimits` field) | Free | Pro (per seat) | Business (per seat) |
|---|---|---|---|
| `max_members` | **10** | unlimited (every user is a seat) | unlimited |
| `max_devices` · `max_tunnel_clients` | 100 · 100 | 1,000 · 1,000 | 5,000 · 5,000 |
| `max_concurrent_sessions` | **1 per org** | 1 per seat | unlimited |
| `video_max_participants` · `meeting_max_minutes` | **10 · 60** | 50 · unlimited | 100 · unlimited |
| `storage_bytes` | 1 GiB | 10 GiB per seat | 50 GiB per seat |
| `relay_bytes_per_month` | 10 GB | 25 GB per seat | 100 GB per seat |
| `magic_dns` · `exit_nodes` · `recordings` | yes · no · no | yes · yes · no | yes · yes · yes |

"Unlimited" is spelled `u32::MAX`, never `Option`: a counted cap reads it as "no cap"
(`count_cap`), and the published JSON carries the number. `billing_tests` reads most of
these cells back through `GET /api/stripe/plans`; the code is the source, this table its
summary.

## 2. One decision point

```mermaid
flowchart TD
    A["a gated action<br/>enroll · invite · upload · start a session · join or run a meeting"] --> S{"plans sold here?<br/>Core::plans_sold"}
    S -->|no: self-hosted| OK[allow · count nothing]
    S -->|yes| E["quota::evaluate_for(plan, seats, mode, limit, used, delta)"]
    E -->|under the cap| OK
    E -->|over| C{established?}
    C -->|yes| R["refuse, in every mode"]
    C -->|no| M{"org's plan_enforcement"}
    M -->|off| OK
    M -->|warn| W["allow, log the line"]
    M -->|enforce| R
    R --> N["FR-102: count the collision for the org"]
    W --> N
```

`services::quota::evaluate_for` (`crates/services/src/quota.rs:301`) is the only place a limit is
compared. Call sites go through `meshharbor_core::quota::check` (`crates/core/src/quota.rs:38`), which adds
two things: the FR-102 collision count per org (`growth_daily`), and `Core::plans_sold`
(§6).

## 3. Which limits ignore the mode

`plan_enforcement` (`off` → `warn` → `enforce`, per org; new orgs start on `warn`) exists to
stage a new gate safely. An **established** limit ignores it and refuses in every mode,
`off` included (`Limit::is_established`, `crates/services/src/quota.rs:93`):

| Established | Since | Why |
|---|---|---|
| devices, tunnel clients | before FR-32 | the original caps; the mode was never meant to reach them |
| members | FR-115 D2 | with per-seat pricing, Free's ten users is the line a team crosses into a paid plan |
| concurrent remote sessions | FR-115 P3 | Free's objective fence, in place of "personal use" detection |
| meeting participants, meeting length | FR-115 P5 | "10 people, 60 minutes" is what Free sells |

Everything else (storage, channels, recordings, exit nodes, MagicDNS, cloud integrations) is
staged by the mode.

## 4. The gates

| Limit | Checked at | Refusal |
|---|---|---|
| devices | enrollment (`crates/modules/fleet/src/agent.rs:234`) | 403, before the single-use token is claimed |
| tunnel clients | `crates/modules/network/src/routes/tunnel.rs:138` | 403 |
| members | invite and admin add (`crates/api/src/routes/invite.rs:199`) | 403 naming the counts |
| storage | upload (`crates/modules/chat/src/file.rs:312`) | 403; the check is `current + incoming`, so a file that exactly fills the quota fits |
| meeting participants | `media:join` on the owner pod (`crates/modules/conference/src/ws_media.rs:286`) | `media:error`; a rejoining participant keeps their seat |
| meeting length | the sweep (`crates/modules/conference/src/meeting_cap.rs:100`) | `room:call_ending_soon` at 55, `room:call_ended {reason: plan_limit}` at 60 |
| concurrent sessions | the hub, after its coalesce (`crates/modules/fleet/src/hub.rs:1577`); with `rc.session_slots` on, a cluster-wide slot claimed on the pod that owns the device before the hub runs (`crates/modules/remote/src/slots.rs`) | `org_session_limit`, naming who holds the slot and where; an external session gets `session_limit` |
| recordings, exit nodes, MagicDNS | `require_feature` at each route | 403 in feature wording ("not available on the Free plan") |

The two fences that are not a request — a meeting that runs long, a session started on
another pod — are where the design is unusual:

- **Meeting length is a sweep, not a timer.** Every pod reads the calls in progress every
  30 s; the warning and the end are writes conditional on the call it read, so two pods act
  once and a restarted meeting is never ended by a stale read. Detail:
  [FR-115 *Meetings, as built*](fr/FR-115-pricing-reshape.md#meetings-as-built-p5).
- **Concurrent sessions are counted by the hub that owns the device.** Tenant affinity puts
  an org's devices and controllers on one pod, so that pod's count is the org's; a request
  relayed from another pod carries the cap its gate read.
- **P3b makes the count cluster-wide** (`rc.session_slots`, on in production since 2026-10-21): one record per
  payer in Redis (`crates/core/src/cluster/session_slots.rs`), claimed atomically, renewed
  every 30 s by the pod that holds the session, and freed within 90 s of a pod dying. An
  org's own sessions and the external (FR-52) sessions its members run for it share its
  slots: the outsider picks the org on `/connect`, from any of theirs, and no paid org is
  needed. An account in no org gets Free's one session, counted against the account. When
  Redis cannot answer, the hub's count decides, as before.

## 5. Seats and billing

```mermaid
sequenceDiagram
    participant UI as billing page
    participant API as meshharbor (saas)
    participant S as Stripe
    UI->>API: POST /api/stripe/checkout {plan, interval, currency}
    API->>API: refuse a currency not on sale · refuse a 2nd subscription (409)
    API->>S: Checkout Session, quantity = seats
    S-->>API: customer.subscription.created / .updated (webhook)
    API->>API: tenants.billing ← plan, status, seats, interval, currency
    loop every 15 min, one pod
        API->>S: subscription item quantity = members who accepted (proration)
    end
    UI->>API: POST /api/stripe/change-plan
    API->>S: swap the item's Price on the live subscription (proration)
```

A seat is a member who accepted; a pending invite is not one. Checkout bills
`quantity = seats` (`crates/services/src/stripe.rs:286`); the reconcile keeps it equal to the member count
(`crates/services/src/stripe.rs:553`, spawned by `crates/modules/saas/src/stripe.rs:173`); a plan change moves the existing
subscription's item instead of starting a second one (`crates/services/src/stripe.rs:442`).

| Setting | Effect | Default |
|---|---|---|
| `MESHHARBOR__STRIPE__PRICE_PRO`, `…__PRICE_BUSINESS` | the monthly Prices (one unit per seat) | — |
| `MESHHARBOR__STRIPE__PRICE_PRO_ANNUAL`, `…__PRICE_BUSINESS_ANNUAL` | the annual Prices (two months free); empty hides annual | empty |
| `MESHHARBOR__STRIPE__CURRENCIES` | the currencies on sale; a currency joins once every Price carries it | `usd` |
| `MESHHARBOR__STRIPE__SEAT_SYNC` | the 15-minute quantity reconcile | on |

## 6. Plans bind only where they are sold

Every org is created on `free`, on every server (`crates/services/src/dao/tenant.rs:284`).
On the hosted service that is a plan; on a self-hosted server it only means nobody sold the
org anything. `Core::plans_sold` (`crates/core/src/state.rs:131`) is true only where the
hosted `saas` module is compiled in and switched on (`crates/api/src/state.rs:298`); the
published self-host image and the compose build both leave it out. With it false,
`meshharbor_core::quota` refuses nothing and counts nothing (`crates/core/src/quota.rs:49`), and
the session cap (`crates/modules/remote/src/controller.rs:745`) and the meeting sweep
(`crates/modules/conference/src/meeting_cap.rs:104`) stand down.

⚠️ Until FR-115 found it, nothing exempted a self-hosted server: the device cap had always
bound its orgs, and FR-115's own new caps would have too, from the next self-host image on.
Each fence now has an integration test on a server without `saas`.

## 7. Kill switches

| Switch | Turns off |
|---|---|
| `MESHHARBOR__RC__ORG_SESSION_CAP=false` | the concurrent-session cap |
| `MESHHARBOR__RC__SESSION_SLOTS=false` | P3b's cluster-wide count: back to P3's count on the device's hub, and external (FR-52) sessions uncapped. On in production; it takes effect on a rollout restart, since the ConfigMap carries no content hash |
| `MESHHARBOR__RELAY_ALLOWANCE__ENABLED=false` | the relay allowance on DERP (P4a): no over-allowance set is published, and the API pods and every PoP drop the one they hold within a period. On in production since 2026-10-21; like the line above, it takes effect on a rollout restart |
| `MESHHARBOR__MEETINGS__FREE_CAP=false` | the meeting-length cap |
| `MESHHARBOR__STRIPE__SEAT_SYNC=false` | the quantity reconcile (the quantity is then set at checkout only) |
| an org's `settings.plan_enforcement = off` | every **staged** limit for that org (never an established one) |
| `MESHHARBOR__MODULES__SAAS=false` | the hosted billing module itself, and with it every plan limit (no plans sold). Not a switch for the hosted service: it also takes checkout away |

## 8. Not built yet

- **The relay allowance on TURN (P4c):** TURN bytes past the plan's allowance are throttled,
  never refused (a host behind symmetric NAT has no other path). Needs per-org TURN
  attribution first. The DERP half (P4a) has been on since 2026-10-21, on the API pods and
  the regional PoPs.
- **Exit nodes on Free (P4d):** after the throttle exists.
