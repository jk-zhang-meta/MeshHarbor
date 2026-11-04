# FR-115 — Plans that give the network away and charge for what costs money

| | |
|---|---|
| **Issue** | [#2557](https://github.com/gjovanov/roomler-ai/issues/2557) |
| **Status** | in progress — P0 and P0-ops done 2026-10-19; P1+P2, P3, P5 and the EUR guard merged 2026-10-20, not yet promoted |
| **Arc** | P3 of the pricing sequence in [`../business-model.md`](../business-model.md) §5 (enforce → meter → **reshape** → keys) |
| **Related** | [FR-32](FR-32-plan-limit-enforcement.md) (the one decision point), [FR-20](FR-20-per-tenant-relay-cost-metering.md) (the ledger), [FR-19](FR-19-peer-relays.md) (org relays), [FR-52](FR-52-cross-org-remote-access.md) (support sessions to other orgs), [FR-102](FR-102-growth-observability.md) (revenue view) |
| **Private annex** | `roomler-ai-docs/gtm/pricing/FR-115-annex-census-2026-10-19.md` — per-org census, account counts, competitor detail |

## Goal

Make the Free plan at least as generous as Tailscale's free plan on the things that cost us
nothing (devices, direct traffic, mesh features, chat), allow commercial use on it outright,
and put the limits on what actually costs money or grows with the customer: **concurrent
remote-desktop sessions**, **relayed bytes**, **meeting time**, and **seats**. Bill paid
plans **per seat**, monthly or annually (two months free), in **USD or EUR**.

## Root cause and evidence

`business-model.md` deferred the reshape until FR-20 had metered a month. It has metered seven
weeks. What the meter and the code show (aggregates; the per-org census is in the annex):

### 1. Almost nothing scales with usage, and devices cost nothing at all

| Cost driver | Measured, whole fleet, 30 days to 2026-10-19 | At `config/relay-costs.toml` prices |
|---|---|---|
| Direct P2P (remote desktop, mesh) | 373 session-hours; 94 % of sessions with a recorded carrier went direct | €0 by construction |
| DERP (`derp_bytes`, attributed per org) | ≈ 30 GB (79 GB since 2026-08-30); median day 0.3 GB, max day 15 GB | ≈ €0.30 |
| coturn TURN (fleet total only) | ≤ ≈ 950 GB egress on the central coturn hosts; 41 allocations on average, 307 at peak | ≤ ≈ €9.50 |
| SFU | 0.03 participant-hours since 2026-08-30 | ≈ €0 |

⚠️ The TURN figure is an **upper bound**: the `eu-central` stats region polls the coturn
workers' host NIC (`crates/core/src/relay_load.rs:28`), which also carries whatever else those
hosts serve. It is still the largest relay figure, and it is **the one relay cost no org can
be charged for today** — FR-20 decided not to build per-tenant TURN attribution
([FR-20](FR-20-per-tenant-relay-cost-metering.md) P3, "reopen when a tenant's TURN volume
becomes material"). A relay allowance makes it material by definition.

Concurrency, from the two busiest orgs: peaks of **4** and **3** simultaneous remote sessions;
p90 session length 7 minutes.

### 2. The tiers as shipped contradict themselves

| Surface | Says |
|---|---|
| Landing page, docs home | "$8 /user/mo" (`ui/src/views/LandingView.vue:130`, `ui/docs/theme/home-layout.ts:72`) |
| In-app billing page | "$8 /mo" (`ui/src/views/billing/BillingView.vue:62`) |
| Stripe checkout | `quantity = 1` — one unit per org (`crates/services/src/stripe.rs:202`) |
| MRR estimate | price × member count (`crates/api/src/routes/cost.rs:68`) |
| `Plan::Pro` | unlimited members (`crates/db/src/models/tenant.rs:441`) |

A 20-person team is quoted $160 and billed $8.

### 3. The one limit a new Free org hits is the one that should not exist

Only `max_devices` and `max_tunnel_clients` are **established** — enforced whatever the org's
`plan_enforcement` mode (`crates/services/src/quota.rs:71` at `c5d36ca84`, before P1). Every other gate runs in `Warn` for
an org created after 2026-08-30, by standing decision (`crates/db/src/models/tenant.rs:58`), so
for a new signup MagicDNS and exit nodes already pass. The advertised "1 concurrent session"
(Free) and "5" (Pro) are enforced **nowhere**: FR-32 withheld the gate because nothing wrote
`remote_sessions` (`crates/services/src/dao/remote_session.rs:52`). That table is written now —
projected from the audit stream (`crates/remote_control/src/audit.rs:3`) — but it is
best-effort: three rows have shown "open" for up to 25 days. **A gate must not count it.**

So the effective Free tier is the inverse of the intended one: devices capped at 3,
concurrency unlimited.

### 4. The market

From the vendors' own pricing pages, 2026-10-19 (detail and URLs in the annex):

| | Free | Paid entry | Limits on |
|---|---|---|---|
| Tailscale | 6 users, unlimited user devices + 50 servers, MagicDNS, exit nodes, SSO, peer relays; **non-commercial** | $8 / seat (Standard), $18 (Premium) | seats |
| NetBird | 5 users, 100 machines, commercial OK | €6 / active user | users + machines |
| TeamViewer | personal use only, commercial-use detection | €13.90/mo: 1 user, **1 channel**, 3 devices; extra channel €43.90 | concurrent channels |
| AnyDesk | personal use only | €24.90/mo: 1 connection, 100 devices; extra connection €37.90 | concurrent connections |
| Zoom / Teams / Meet | group meetings 40 / 60 / 60 min | $14–17 / $4 / $7 per user | users; free fenced by meeting length |

Mesh vendors give devices away and charge per seat; remote-desktop vendors charge per
concurrent session; meeting vendors fence free by meeting length; nobody meters relay
bandwidth on a price list (Tailscale lowers DERP quality instead).

## Decisions (operator, 2026-10-19)

| # | Decision |
|---|---|
| D1 | **Per seat.** A seat is a non-pending member of the org; the Stripe subscription quantity is the seat count and follows membership changes with proration. |
| D2 | **Free keeps 10 users, and the cap is enforced** — established, so `plan_enforcement` cannot switch it off. Paid plans have no user cap; every user is a billed seat. |
| D3 | **Commercial use is allowed on Free**, and said so plainly on the landing, pricing and billing pages and in the announcement. The fence is objective — one concurrent session, no support sessions to other orgs — never "personal use" detection. |
| D4 | **Over the relay allowance: throttle, never refuse.** Supersedes `business-model.md` §6 rule 4 ("relayed connections refused"): for a host behind symmetric NAT or a full-tunnel VPN the relay is the only path, so refusing it means the product stops working. Direct traffic and org-relay traffic are never counted. |
| D5 | **Annual billing at two months free** (annual = 10 × monthly), and **EUR prices** beside USD. |
| D6 | **Clean up the orphaned orgs** (owner account gone, test debris from 2026-02). |
| D7 | **Tell the users** — one email, sent once the new plans are live, saying only what is live. |

## Key design

### The ladder

| | **Free** | **Pro** | **Business** | **Enterprise** |
|---|---|---|---|---|
| Price | 0 — commercial use allowed | $8 / €8 per seat per month; $80 / €80 per seat per year | $16 / €16 per seat per month; $160 / €160 per seat per year | custom |
| Users | **10, enforced** | per seat | per seat | per seat |
| Devices · tunnel clients | **100 · 100** (was 3 · 3) | 1,000 · 1,000 (was 30) | 5,000 · 5,000 (was 300) | custom |
| MagicDNS | **yes** (was Pro) | yes | yes | yes |
| Exit nodes | **yes, from P4d** (after the throttle exists) | yes | yes | yes |
| Concurrent remote sessions | **1 per org, enforced** | 1 per seat | unlimited (fair use) | unlimited |
| Support sessions to other orgs (FR-52) | — | yes | yes | yes |
| Relay (DERP + TURN) at full speed | 10 GB / month, then throttled | 25 GB per seat, pooled | 100 GB per seat, pooled | custom |
| Own relays (FR-19) | unmetered | unmetered | unmetered | unmetered |
| Meetings | 10 people, 60 minutes | 50 people | 100 people, recordings | custom |
| Storage | 1 GB | 10 GB per seat | 50 GB per seat | custom |
| Channels, history | unlimited | unlimited | unlimited | unlimited |

Plan ids stay `free` / `pro` / `business`: they are stored in tenant documents and matched in
the webhook, so renaming one is a migration (`crates/services/src/stripe.rs:337`).

### Limits become a function of plan **and** seats

`Plan::limits()` (`crates/db/src/models/tenant.rs:411`) is a pure function of the plan, and
`quota::evaluate` takes only the plan (`crates/services/src/quota.rs:258` at `c5d36ca84`; P1 added `evaluate_for`). Per-seat
allowances (concurrency, relay, storage) need the billed seat count, so the tenant's
`BillingInfo` gains `seats` (the subscription quantity, written by the webhook) and the
limits are computed from `(plan, seats)`. Free has no seats; a paid org whose webhook has not
landed yet is computed at one seat, the floor, so a missing number can only under-grant.

### Plans bind only where they are sold

Every org is created on `free` (`crates/services/src/dao/tenant.rs:284`), on every server.
On the hosted service that is a plan; on a self-hosted server it is only the absence of
one. So `Core::plans_sold` (`crates/core/src/state.rs:131`) is true only where the hosted
`saas` module is compiled in and switched on (`crates/api/src/state.rs:298`). The published
self-host image and the compose build are both built without it. With it false, the one
decision point refuses nothing and counts nothing (`crates/core/src/quota.rs:49`), and the
two fences that read the plan outside it stand down too: the session cap
(`crates/modules/remote/src/controller.rs:745`) and the meeting sweep
(`crates/modules/conference/src/meeting_cap.rs:104`).

⚠️ Found while documenting P5, after P1 and P3 had merged. Without the flag, P1's
established member cap, P3's one session at a time and P5's 60-minute meeting would have
bound every self-hosted org from the next self-host image on. By the same code, the device
cap had bound self-hosted orgs since FR-32 (three devices), which the README's "unlimited
devices" contradicted. The self-host image is published by hand, last on 2026-10-12, so no
self-hosted server ran any of FR-115's caps.

### Per-seat checkout and the quantity sync

```mermaid
sequenceDiagram
    participant UI as Billing page
    participant API as /api/stripe/checkout
    participant S as Stripe
    participant W as /api/stripe/webhook
    participant M as membership routes
    UI->>API: plan, interval (month|year), currency (usd|eur)
    API->>API: seats = non-pending members (min 1)
    API->>S: Checkout Session (price by plan+interval, currency, quantity = seats)
    S-->>UI: hosted checkout → success_url
    S->>W: checkout.session.completed / customer.subscription.*
    W->>W: plan, status, seats, interval, currency → tenants.billing
    M->>M: member added / removed / left
    M->>S: subscription item quantity = seats (proration)
    S->>W: customer.subscription.updated → seats
```

Prices are configured per (plan, interval) — `price_pro`, `price_business` (monthly, live
since 2026-07-27) plus `price_pro_annual`, `price_business_annual` — each a Stripe Price with a
USD amount and an EUR `currency_options` entry, so one id serves both currencies and checkout
names the currency. An absent annual id hides the annual option rather than failing checkout,
the same contract as an empty monthly id today (`crates/services/src/stripe.rs:141`).

A currency is on sale only once `stripe.currencies` names it (`MESHHARBOR__STRIPE__CURRENCIES`,
default `usd`, `usd,eur` once O1 lands). The billing page starts a European browser on EUR,
so a currency the live Prices cannot charge in must stay off the page, not just be refused at
checkout. `get_plans` lists only the currencies on sale, the page shows its currency toggle
only when there is a choice, and checkout refuses any other before it reads anything from
Stripe. A promote therefore does not wait for O1: EUR and annual appear when the operator
switches them on.

### The concurrency fence

Counted **in the hub**, at session start, after the authz gate and the FR-101 ceiling
(`crates/modules/remote/src/controller.rs:80`) — never from `remote_sessions`. The count is
the controller's org's live sessions; a session to another org's device (FR-52) counts against
the **controller's** org, which may live on the other pod, so the count is kept in Redis as
leases that expire with the session rather than read from one pod's `DashMap`. Refused with a
message naming the session that holds the slot (device and person) so the person can end it;
a live session is **never** ended by the fence (`business-model.md` §6 rule 4). Established,
like the device cap: no org is over it today.

**As built (P3).** The authz gate reads the cap from the device's org
(`org_session_cap_of`, `crates/modules/remote/src/controller.rs:652`) and hands it to the hub
in `DispatchCtx`, and in the body of a request relayed to the pod that owns the device. The
hub counts that org's live sessions after its coalesce, so a re-asked session is not a
second one (`crates/modules/fleet/src/hub.rs:1577`). Tenant affinity puts an org's devices
and its controllers on one pod, so that pod's count is the org's. Redis leases are needed
only for the one case affinity cannot place: a session to **another** org's device, which
must count against the controller's org. That is **P3b** (#2637), live since 2026-10-21 with
`rc.session_slots` on. With that switch off, a cross-org session counts against the device's org, and an
outsider's session (FR-52's extauth path) opens
uncapped. A refusal is `org_session_limit`
(`crates/remote_control/src/error.rs:41`), which the viewer does not retry
(`ui/src/composables/useRemoteControl.ts:732`). It names the person and the device holding
the slot, and a Pro org at its cap (one per billed seat) is told the way past it is a
session ending or Business. Kill switch `rc.org_session_cap = false`.

### P3b, as proposed: a cluster-wide session count that heals itself (O6 + O7 decided 2026-10-20)

**Why P3's count cannot carry it.** P3 counts on the hub that owns the device
(`crates/modules/fleet/src/hub.rs:1565`). Under tenant affinity, that hub holds every live
session of the device's org, so the count is complete for a same-org session. A cross-org
session breaks that assumption: the org that pays is the controller's, and its sessions live
on whichever pods hold the devices they reach. Today FR-52's external path opens its session
uncapped (`crates/modules/remote/src/extauth.rs:305`), waiting for this phase. P3's own count
also has a documented race: the count and the insert are two steps, so two starts in the same
instant can both pass (`hub.rs:1573`).

**The record: session slots in the cluster directory.** C-1's directory
(`crates/core/src/cluster/directory.rs`) already keeps per-entity records in Redis on exactly
these terms. Redis is a directory, not a database: every record can be re-derived from a live
registry, a reader fails soft to the pod-local answer, and TTL expiry backs up explicit
release. Its records live 90 s, three times the 30 s heartbeat (`directory.rs:25`). P3b adds
one namespace on the same discipline:

| Key | Holds | Written by |
|---|---|---|
| `rc:slots:{org}` (sorted set) | member = session id, score = lease expiry | the hub that owns the session |
| `rc:slot:{session}` (hash, same TTL) | the holder: user, device, kind (`same_org` / `external`) | the same hub |

```mermaid
sequenceDiagram
    participant G as authz gate (controller.rs / extauth.rs)
    participant H as the hub that owns the device
    participant R as Redis rc:slots:{org}
    G->>G: whose org pays: the device's (same org) or the one the outsider acts for (external)
    G->>H: rc:session.request + SessionCharge {org, cap, kind}
    H->>R: CLAIM (Lua): drop expired · already mine? renew · fewer than cap? add
    alt claimed
        R-->>H: ok
        H->>H: open the session
        loop every 30 s while it is live
            H->>R: renew this pod's leases (one pipeline)
        end
        H->>R: on close: remove the member and the holder hash
    else full
        R-->>H: one holder
        H-->>G: org_session_limit, naming who holds the slot and on which device
    else Redis unreachable
        H->>H: fail soft: P3's pod-local count for a same-org session, an external one is allowed, and counted
    end
```

**Why this is durable.**

- **One atomic claim.** The Lua claim drops expired members, checks the count and adds the
  session in one step, so the race at `hub.rs:1573` closes.
- **It heals itself.** A lease lives 90 s and is renewed every 30 s by the pod that holds the
  session. A pod that dies stops renewing, and its slots free themselves within 90 s. A Redis
  restart loses the set, but renewal is an upsert, so within one renewal round every live
  session is back in it. Nothing has to be reconciled by hand.
- **Idempotent.** The member is the session id, so a retried claim for the same session
  renews it rather than spending a second slot. P3's duplicate coalesce stays true across
  pods.
- **Fails soft, never closed.** A Redis error never refuses a session, the same rule as every
  FR-115 fence: never refuse on a guess. A same-org request falls back to P3's hub count,
  which is complete under tenant affinity. An external request is allowed and counted
  (`rc_slot_claim_failed_total`).
- **One count for both kinds.** Same-org sessions move onto the same record, so an org's own
  sessions and the support sessions its members run into other orgs share its plan's slots.
  P3's hub count stays as the fallback.

**Whose quota an external session uses (O6 + O7, decided by the operator 2026-10-20).** FR-52's
outsider is an account (`docs/fr/FR-52-cross-org-remote-access.md:388`). That account is not a
member of the device's org, and it may belong to several orgs of its own, or to none.

- **No paid org is needed (O7).** Any account that may start an external session today still may.
- **The session uses the quota of the org it is for, at that org's tier (O6).** The `/connect`
  page asks which of the outsider's orgs the session is *for*, from **all** of them, Free
  included, and needs no question when there is one. The session, its slot and its audit row all
  carry that org, and the session takes one of that org's concurrent-session slots
  (`max_concurrent_sessions` for its plan and seats, the same number same-org sessions use). A
  Free org therefore runs one session at a time, whether it is to its own device or someone
  else's.
- **An account in no org uses Free's quota, counted against the account** (`rc:slots:user:{id}`):
  one external session at a time. *An org-less account has no tier of its own, so this case was
  the session's application of the decision; the operator confirmed it on 2026-10-21.* It keeps FR-52's
  helping-a-friend case working without membership.

The rejected alternative was to charge the device's org. That is always defined and needs no
picker, but it contradicts AC6 as written and puts a support desk's sessions on its customer's
plan.

**Kill switches:** `rc.org_session_cap = false` lifts every cap. `rc.session_slots = false`
returns to P3's hub count, with external sessions uncapped as they are today.

**Before the field.**
- **Unit:** the Lua claim's four outcomes against a real Redis: claim, renew-mine, full (with
  the holder), and expired-dropped.
- **Integration, two pods:**
  1. A Free org A holds a session to its own device on pod 1.
  2. An external session from A to org B's device on pod 2 is refused with `org_session_limit`,
     naming the first; the first session is untouched.
  3. Pod 1's renewal stops, and the slot frees within 90 s.
  4. An account in no org holds one external session; its second is refused, naming the first,
     and the first is untouched.
- **Field:** the same on prod with two test orgs, after FR-52's P4f field run.

**Not in P3b:** metering an external session's relay bytes (FR-52 P5, its F3), and the
analytics surface for external sessions.

### The relay allowance

```mermaid
flowchart LR
    D["DERP forward_frame<br/>(derp.rs:584)"] -->|bytes| L[("stats_usage<br/>per org, per minute")]
    T["coturn<br/>--redis-statsdb (P4b)"] -->|bytes per allocation| L
    L --> MTD["month-to-date per org<br/>(60 s flush)"]
    MTD -->|over allowance| F{{"over-allowance set"}}
    F --> TB["DERP token bucket<br/>for flagged networks only"]
    F --> TC["TURN: credentials on a<br/>rate-capped realm"]
    DIR["direct P2P"] -. never counted .-> X(( ))
    OR["org relay (FR-19)"] -. never counted .-> X
```

- DERP already meters per network on the forward path
  (`crates/modules/network/src/derp.rs:683`). The throttle adds **one** set lookup on that
  path, consulted only for networks the 60 s flush flagged; the path must stay within FR-18's
  budget, measured with the same bench FR-20 used (`derp.rs:704`).
- TURN attribution is FR-20's deferred P3, taken up with the option FR-20 already chose
  (`--redis-statsdb`; the username is `<expiry>:<id>`, `crates/remote_control/src/turn_creds.rs:6`).
- Throttled, never refused (D4). The tenant analytics page shows usage against the allowance in
  units, never money (FR-20's decision stands).

### P4a — the DERP throttle (approved by the operator 2026-10-20)

**What it must not break.** DERP over TLS :443 is the floor that always connects (pillar 2,
commitment 2). A throttle that delays a WireGuard handshake past its retry window turns "slow"
into "down" for exactly the hosts that have no other path: symmetric NAT, full-tunnel VPNs. So
the throttle shapes **bulk only**:

| Frame class (`crates/remote_control/src/derp_frame.rs:39`) | Throttled when over allowance? |
|---|---|
| WireGuard types 1–3 (handshake initiation, response, cookie) | **never**: tiny, and the handshake must complete |
| disco (`DISCO_MAGIC`), the path-upgrade probes | **never**: they are how a pair climbs back off DERP |
| WireGuard type 4 (transport data) | yes |
| tunnel-class payloads (`quic-derp-v1`) | yes, on top of R4's existing ~3 Mbit/s per-source cap |

**The pieces.**

```mermaid
flowchart LR
    FL["usage flush, every pod<br/>(derp.rs:178)"] --> L[("stats_usage")]
    PP["PoP /stats poll<br/>(relay_load.rs:216)"] --> L
    L --> J["allowance job, one pod, every 5 min:<br/>month-to-date per org vs<br/>relay_bytes_per_month × seats"]
    J -->|plans_sold only| S[("over-allowance set<br/>(Redis, networks of flagged orgs)")]
    S --> A["each API pod: refresh every 60 s<br/>→ DashSet lookup in forward_frame"]
    S --> P["each PoP: pushed on the /stats poll,<br/>signed with the ticket key"]
    A & P --> TB["per-network token bucket<br/>at the O3 rate"]
```

- **Month-to-date** is the ledger FR-20 already writes: `derp_bytes` from both collection
  points (the API pods' forward path, the PoPs' `/stats`), summed per org since the first of
  the month (UTC). One pod computes it every 5 minutes under a Redis claim, the same shape as
  the seat reconcile, and only where `Core::plans_sold`.
- **The set is per network**, because that is what `forward_frame` holds; the job resolves
  org → networks. An org leaves the set when its month rolls over or its plan's allowance grows
  (an upgrade takes effect within one job period).
- **API pods** refresh a local `DashSet<network_id>` every 60 s. The forward path adds one
  lock-free lookup, and only for frames already past the ACL; it is measured with FR-20's bench
  (`crates/modules/network/src/derp.rs:704`) against FR-18's latency budget before it ships.
- **PoPs are DB-free and must stay so.** Tickets cannot carry the flag: they live 24 h and are
  checked once, at connect (`crates/remote_control/src/derp_ticket.rs:33`). Instead the API,
  which already polls each PoP's `/stats`, sends the PoP the set on that poll, signed with the
  ticket signer, which the PoP already verifies (`crates/derp-relay/src/main.rs:50`). A PoP
  that has not heard a fresh set within 3 poll periods drops it: it fails open, never closed.
- **The bucket** is per network (the org's mesh), at O3's rate: 1 Mbit/s on Free, 4 Mbit/s on
  paid plans. Over the bucket, a frame is dropped, as R4 already does for tunnels: WireGuard
  rides UDP semantics, and TCP inside it backs off to the rate.

**The measurement O3 asks for, before it ships.** On the fleet, a pair held on DERP (UDP
between the two hosts blocked, so only the floor carries), at 1 and 4 Mbit/s: a 100 MB copy
over the mesh (roomler SSH), an interactive shell's keystroke latency, and a remote-desktop
session riding the org's overlay (#1882's `rc_overlay`: its ICE may use the WireGuard overlay).
A session's own WebRTC path relays through TURN, not DERP, so only an overlay-riding session
meets this throttle; TURN's is P4c. Then a WireGuard handshake storm (restart one side) to show
the handshake path stays unthrottled. If 1 Mbit/s makes the mesh unusable, the Free rate goes
up, not the policy.

**Kill switch:** `relay_allowance.enabled = false` (empty set, no job). **Surface:** the org's
analytics page shows relayed bytes against the allowance in units, never money (FR-20), and
says when the throttle is on.

**Not in P4a:** TURN (P4b attributes coturn bytes per org with `--redis-statsdb`, P4c moves an
over-allowance org's credentials to a rate-capped realm), and exit nodes on Free (P4d, after
the throttle exists).

### P4b, as proposed: per-org TURN bytes from coturn's statistics DB (AC8, approved 2026-10-20)

**Where FR-20 left it.** FR-20's P3 weighed per-tenant TURN attribution and deferred it on
purpose (`docs/fr/FR-20-per-tenant-relay-cost-metering.md`, its P3 row). coturn's Prometheus
labels are realm-only. Per-username labels would be a cardinality bomb, because a REST username
carries its expiry and is never reused. `--redis-statsdb` is sound, and FR-20 recommends it
when this is taken up. AC8 takes it up. `Meter::TurnBytes` already exists
(`crates/services/src/dao/stats.rs:80`), but nothing writes it.

**What coturn publishes.** This is from its source (`src/apps/relay/ns_ioalib_engine_impl.c`,
read 2026-10-20). The cluster's coturn is 4.18.0, linked with hiredis.

| Channel | When | Payload |
|---|---|---|
| `turn/realm/<realm>/user/<username>/allocation/<id>/traffic` | every 4096 packets of the allocation | that period's `rcvp=…, rcvb=…, sentp=…, sentb=…` (a delta) |
| `…/allocation/<id>/total_traffic` | once, when the allocation is deleted | the allocation's totals, in the same format |
| `…/traffic/peer`, `…/total_traffic/peer` | the same, for the relay ↔ peer leg | the same format |

**The design.**

1. **The username names the paying org: `{expiry}:{principal}:org-{org}`.** Four issuance
   paths know the org: the hub's per-session issuance (the session's org), a meeting's
   credentials (the room's org), an overlay pair's relay grant and a tunnel's QUIC credentials
   (the node's or tunnel's org). coturn reads the expiry before the first `:` and HMACs the
   whole username, so neither coturn nor any client sees a difference. The session-less
   pre-fetch (`GET /api/turn/credentials`) knows no org. Bytes relayed under it are counted as
   unattributed and logged, never guessed; that is FR-20's rule.
   ⚠️ The `org-` marker, not the position, is what makes the org readable. An overlay pair's
   principal is itself `{node}:{node}` (`overlay::pair_key`), so an uncharged pair username
   also ends in an ObjectId, which a "last hex part" rule would book as an org.
2. **Cluster coturn** (`coturn-worker-1..3` in the `coturn` namespace) points `redis-statsdb`
   at the cluster's Redis. The API subscribes to `…/total_traffic` and `…/total_traffic/peer`.
   Both API pods receive every message, so the first pod to win a `SET NX` on the allocation
   leg records it, and no allocation is counted twice. The key is the username, the
   allocation id and the leg, because coturn numbers allocations per process and two workers
   can reuse an id. The bytes counted are what coturn sends
   out: `sentb` toward the client plus the peer leg's `sentb`, just as DERP counts the bytes it
   forwards. They are written per org as `turn_bytes`, with the same `add_usage` the DERP
   flusher uses.
3. **PoP coturn** (the four regional PoPs, docker-compose) gets a local Redis on each PoP for
   coturn's statistics. The PoP's `derp-relay` daemon subscribes and keeps per-org totals. It
   reports them on the `/stats` poll the API already makes (`crates/core/src/relay_load.rs`),
   and the API turns them into `turn_bytes`. The PoP stays database-free.
4. **Exact, but not immediate.** `total_traffic` lands when the allocation ends, so a long
   allocation reports late. For AC8, which is accounting, that is enough. P4c's throttle needs
   fresher numbers and can add the 4096-packet deltas then.
5. **Kill switch:** `relay_allowance.turn_attribution = false` means no subscription and no
   TURN bytes read from the PoPs.

**Rollout, one worker at a time.** The workers run `coturn/coturn:latest`, unpinned, so a
restart can pull a different coturn than the one verified here. **Pinning the running version
(4.18.0) comes first.** Their ConfigMaps (`coturn-worker-N-config`) live outside the deploy repo
and move into it before they are edited, so the change is reviewable and reversible. Then one
line (`redis-statsdb=…`) goes to worker-1. It is verified (a TURN-only session still connects,
and the statistics arrive), then applied to workers 2 and 3. The PoPs follow.

**Before the field.**
- **Unit:** the parser on coturn's exact payloads, the username split, and the egress sum.
- **Integration:** a fake publisher on the test Redis produces `turn_bytes` rows for the org,
  with each allocation counted once even with two subscribers.
- **Field:** a session forced through TURN (`iceTransportPolicy: relay`), after which
  `stats_usage` shows `turn_bytes` for that org (AC8). Check it before the coturn flip and after.

### Meetings

Free meetings end at 60 minutes with a warning at 55; the participant caps become
established. The SFU's unit cost (`sfu_participant_hour = 0.004` in `relay-costs.toml`) has
never been checked against a real call; P5 measures it from `stats_call_user` before any
number is advertised beyond what the current single-worker room is known to carry.

### Meetings, as built (P5)

**A sweep, not a timer.** A timer lives in the pod that started the call, and a rolling
deploy restarts pods: the call would outlive its timer and run uncapped. Every pod reads
the calls in progress every 30 s (`crates/modules/conference/src/meeting_cap.rs:248`) and
decides each one with `quota::evaluate_for` on the new `Limit::MeetingMinutes`, read as
"may it run one more minute?" (`meeting_cap.rs:58`). The comparison stays in the one
place plan limits are compared, and like the device cap it is **established**: `warn`,
every new org's default, does not soften it (`crates/services/src/quota.rs:93`). So does
`VideoMaxParticipants`, Free's other meeting fence; its count reads the owner pod's room,
so it can only under-count and fails open.

```mermaid
sequenceDiagram
    participant S as sweep (every pod, 30 s)
    participant R as rooms (Mongo)
    participant M as members' sockets
    S->>R: calls in progress that started 55+ minutes ago
    S->>S: step(plan, seats, mode, elapsed, warned)
    alt 55 ≤ minutes < 60 and not warned
        S->>R: claim_cap_warning(room, call)
        R-->>S: won by one pod
        S->>M: room:call_ending_soon {ends_at, max_minutes, plan}
    else minutes ≥ 60
        S->>R: end_call_if_current(room, call)
        R-->>S: won by one pod
        S->>S: count the collision · close the call session · close the media island
        S->>M: room:call_ended {reason: plan_limit, max_minutes, plan}
    end
```

| Guard | Where | What it prevents |
|---|---|---|
| The warning is a write conditional on `current_call_id = call` and `cap_warned_call_id ≠ call` | `crates/services/src/dao/room.rs:743` | two pods warning one meeting; warning a meeting that ended |
| The end is a write conditional on `current_call_id = call` and `in_progress` | `room.rs:762` | ending the **next** meeting in a room restarted between the sweep's read and its write |
| The FR-102 collision is counted after the won end | `meeting_cap.rs:198` | a meeting counted twice when two pods reach it together |
| `meetings.free_cap = false` | `crates/config/src/settings.rs` (`MeetingsSettings`) | the kill switch: no meeting is warned or ended |

Precision is one sweep period: the warning lands between 55:00 and 55:30, the end between
60:00 and 60:30. The browser counts the minutes left from `ends_at`, not from the moment
the warning arrives (`ui/src/utils/meetingCap.ts`). A meeting started again after the end
is a new call with its own sixty minutes. A meeting the sweep first sees past 60 minutes
is ended at once, **without** the warning, because `step` checks the end before the
warning. That happens only if no pod swept for five minutes or more (an outage of every
pod, or a meeting already running when P5 first deployed).

⚠️ A call whose row the startup stale-call reset ends (`maintenance.rs:21`, on every boot,
under the startup lease) while its media lives on in the surviving pod is no longer
in progress, so the sweep does not see it. That gap is in call state, which predates
P5. The cap can lose at most the minutes of one meeting that spans a deploy.

**The SFU measurement P5 owed came back empty**: the 90 days to 2026-10-20 held too
little conferencing to fit a unit cost from (the field log; counts in the private annex),
so there is no field number for what one room carries. A room is one
mediasoup router on one worker, which mediasoup's own scalability guidance puts at
roughly 500 consumers. A meeting where everyone sends a camera and a microphone needs
2·N·(N−1) consumers: 180 at 10 people, about 4,900 at 50 and 19,800 at 100. Free's 10
fits. Pro's 50 (P1 raised it from 10) and Business's 100 (unchanged) do not, unless a
room is piped across workers. That is O4.

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P0 | Spec, registry row, issue | — | ✅ #2560 (`c5d36ca84`) |
| P0-ops | Tombstone the orphaned orgs (owner account gone), with an export first | restore from the export | ✅ 2026-10-19 21:32Z — 62 of 62, backup verified first; **deleted outright 2026-10-20** (O5), from a second verified export |
| P1 | The ladder: `Plan::limits_for(seats)`, Free = 10 users established + 100 devices + MagicDNS, unlimited chat; plan copy, commercial-use message on landing / docs / billing; snapshot tests | revert (data only) | ✅ merged #2565 (`ca7c23bdc`), promoted 2026-10-20 (`hosted-20261020-9776afb`); AC1 and AC2 field-verified on prod |
| P2 | Per-seat Stripe: quantity at checkout, annual + EUR prices, quantity sync with proration, webhook stores seats/interval/currency/plan, plan change on the live subscription, summary route; integration tests against a recording fake Stripe; then Stripe **test mode** and an e2e checkout with a test card | `stripe.seat_sync = false`; absent annual ids hide annual | ✅ merged #2565 (`ca7c23bdc`) against the fake; proven against Stripe's test mode, including a test-card checkout in a real browser (#2604, AC3 + AC4). A Free `year` price that put annual on every page was fixed by #2603 |
| P3 | Concurrency fence: counted by the device's hub, established, start-only, names the holder | `rc.org_session_cap = false` | ✅ merged #2571 (`83e9a9772`); field-verified on prod for one org (AC6's first half); the cross-org half is P3b |
| P3b | A cross-org session counts against the org it is for, at that org's tier (Redis leases); no paid org needed; an account in no org gets Free's one session | `rc.org_session_cap = false`; `rc.session_slots = false` | ✅ **live and field-verified 2026-10-21**: #2637 (`726654b35` since the 2026-10-21 history rewrite), session slots in the cluster directory (*P3b, as proposed*), with O6 + O7 as the operator decided them on 2026-10-20. The integration lane ran all 11 `org_session_cap` tests, two pods among them. Promoted with `hosted-20261021-adbdadc`, then `rc.session_slots` switched on (deploy `596782e`), on the operator's go. In the field, both halves of AC6 hold: same-org with the slot doing the refusing (red, then green), and cross-org through FR-52's external path (field log) |
| P4a | Relay allowance on DERP: month-to-date, over-allowance set, token bucket, analytics quota slot | `relay_allowance.enabled = false` | 🟡 **live 2026-10-21**, switched on in the deploy repo (`f5940b7`) on the operator's go. At that moment 0 orgs were over their allowance, so it held nobody. On prod, AC7's throttle and direct-path halves hold (field log); still owed are its org-relay clause and O3's usability items. The design was approved 2026-10-20 (*P4a — the DERP throttle*). P4a-1 (#2616, `d6235e5ee`) is on the API pods; P4a-3 (#2629, `b2c66f102`) is the analytics surface; P4a-2 (#2633, `11f18c33a`) merged 2026-10-20: the PoPs throttle by the set the API signs and pushes on its `/stats` poll, and a PoP that holds no set throttles nothing. All four PoPs have run it since 2026-10-21 06:11Z, and the API's push has reached every one since the 12:46Z promote (field log) |
| P4b | Per-org TURN attribution (`--redis-statsdb` → `turn_bytes`) | `relay_allowance.turn_attribution = false`; coturn flag off | 🟡 designed 2026-10-20 (#2619); P4b-1 (#2622, `54a3709ff`) merged dark: TURN usernames name the paying org (`:org-`), and the statsdb collector is off. Next: pin coturn (it runs `:latest`), bring the worker ConfigMaps into the deploy repo, add `redis-statsdb` one worker at a time; P4b-2 the PoPs |
| P4c | TURN throttle for over-allowance orgs | `relay_allowance.turn = false` | ⬜ |
| P4d | Exit nodes on Free | revert (data only) | ⬜ |
| P5 | Meetings: Free 60-minute cap, established participant caps, measured SFU cost | `meetings.free_cap = false` | ✅ merged #2583 (`8ed9ccb34`); AC9 field-verified on prod 2026-10-20 in real time (warned at 55:00, ended at 60:00); the SFU measurement found nothing to measure (O4) |
| P6 | Announcement email to real users, once P1 + P2 are live | — | ✅ sent 2026-10-20 13:55Z to every real user, after #2603's promote and an all-green AC5 re-check; the send log is in the private annex |
| P7 | **Docs**: `business-model.md` (§4 ladder, §6 rule 4, §7), `compare/vs-tailscale.md`, a plans-and-limits page, with diagrams, linked from `docs/README.md` | — | 🟡 `business-model.md` and `vs-tailscale.md` landed with P0/P1; [`plans-and-limits.md`](../plans-and-limits.md) merged #2592 (`94f9ab2c5`); P4's docs come with P4 |

## Acceptance criteria

- [x] AC1 — A new Free org enrolls its 100th device and is refused the 101st with the plan message (prod).
- [x] AC2 — A Free org's 11th member is refused, with `plan_enforcement` set to `warn` **and** to `off` (prod).
- [x] AC3 — Checkout in Stripe test mode, monthly and annual, USD and EUR, charges quantity = seats, and the webhook stores plan, seats, interval and currency (integration test against test mode **and** an e2e checkout with a test card).
- [x] AC4 — Adding and removing a member of a paid org changes the subscription quantity with a proration (integration test against test mode).
- [x] AC5 — Landing page, docs home and billing page show the same per-seat prices, the annual price and EUR, and say Free allows commercial use (e2e).
- [x] AC6 — A Free org's second concurrent remote session is refused at start with a message naming the session holding the slot, and the first session is untouched (prod, two browsers). A cross-org session counts against the controller's org.
- [ ] AC7 — A Free org over its relay allowance still connects over DERP at the throttled rate; a direct transfer and an org-relay transfer add **zero** relay bytes (unit, falsifiable as FR-20's; prod).
- [ ] AC8 — `turn_bytes` is populated per org from coturn (prod).
- [x] AC9 — A Free meeting is warned at 55 and ended at 60 minutes (prod).
- [x] AC10 — The orphaned orgs are tombstoned from an export, and no per-org view counts them (prod). Since 2026-10-20 they are deleted outright (O5), so no view can.
- [x] AC11 — The announcement reached every real user and no internal or test account (send log).
- [ ] AC12 — Docs updated or created in the house style with diagrams, and linked from `docs/README.md`'s index.

## Open decisions

| # | Question | Default until answered |
|---|---|---|
| O1 | Live Stripe prices: create the annual Prices and the EUR currency options in the live account, then set `MESHHARBOR__STRIPE__PRICE_PRO_ANNUAL`, `…__PRICE_BUSINESS_ANNUAL` and `MESHHARBOR__STRIPE__CURRENCIES=usd,eur` | **Decided 2026-10-20: yes, and done.** Both monthly Prices carry an EUR option at the USD number; annual Prices exist on the same products; the prod ConfigMap names them and sets `usd,eur` (the field log) |
| O2 | Do pending invites count toward Free's 10? | no — a seat is a member who accepted |
| O3 | Throttled rate for an over-allowance org | 1 Mbps per org on Free, 4 Mbps on paid plans, measured before it ships |
| O4 | Pro's 50 and Business's 100 people per meeting, against one mediasoup worker per room (*Meetings, as built*) | the numbers stay as published; a synthetic-participant load test measures what one room carries, then either a room pipes across workers or the published numbers come down to the measured one |
| O5 | AC10's "no per-org view counts them". Admin stats, plan compliance and weekly active orgs exclude the 62 tombstoned orphans. FR-102's growth **Orgs** list shows them with an *archived* chip, and a cohort view asked for more than its default 26 weeks would count them in their February cohorts. Hiding archived orgs outright would also hide an owner's own archive, which is the churn signal that list is for | **Decided 2026-10-20: remove them completely, and done.** Every document of the 62 is deleted (the field log), so no view lists or counts them |
| O6 | Whose plan pays for an external (FR-52) session (*P3b, as proposed*)? | **Decided 2026-10-20 (operator): it uses the quota of the org it is for, at that org's tier.** The outsider picks the org on `/connect`, from all of their orgs, and the session takes one of that org's concurrent-session slots. An account in no org uses Free's quota (one session), counted against the account; the operator confirmed this case on 2026-10-21 |
| O7 | Do accounts in no paid org get no external sessions? | **Decided 2026-10-20 (operator): no, no paid org is needed.** FR-52's helping-a-friend case keeps working without membership |

## Out of scope

SSO / SCIM (not built), mobile clients, offline licence keys for self-hosted Enterprise
(`business-model.md` §5 P4), right-sizing the regional PoP fleet (`business-model.md` §7
decision 5), and any limit on a self-hosted server — self-hosting stays free and unlimited.

## Field-verification log

| Date | What | Result |
|---|---|---|
| 2026-10-19 | Read-only prod census (ledger, sessions, relay stats, memberships) | the numbers in *Root cause*; per-org detail in the annex. ⚠️ A first pass summed BSON `Long`s with JS `+`, which concatenates: the fleet DERP total read 1.03e34 GB while every per-row figure was right. Re-run with `Number()` conversion and checked against the weekly sums |
| 2026-10-19 | P0-ops — the orphaned orgs | Selection: a missing owner account, outside the exclusion set, no live member, and no devices, overlay, messages or files: **62**, all created 2026-02. Exported with their 100 memberships, 62 rooms, 83 room members and 310 roles to a private backup on the ops host, and the file checked before any write. Recomputed at write time and matched the backup (62 = 62); `deleted_at` + `is_archived` set on 62 of 62. Live orgs went from 77 to 15 |
| 2026-10-19 | Found while building P2 | Two live billing bugs beyond the ones in *Root cause*. (1) A Pro org's "Switch to Business" ran a **second checkout**, which starts a second subscription: two bills. (2) `customer.subscription.updated` wrote only the status, so a plan changed in Stripe's portal **never reached the org**. Both fixed in P2: a live subscription refuses checkout (409) and changes go through `change-plan`; the webhook maps the price to the plan. No org's billing record shows a second subscription |
| 2026-10-20 | P5's SFU measurement — read-only prod census of `call_sessions` and `stats_call`, 30 and 90 days | **Nothing to measure**: too little conferencing in the window to fit a unit cost from, so `sfu_participant_hour` stays unverified. Neither fence would have changed a meeting in it — none on a capped plan ran past 60 minutes or held more than 10 people. Counts in the private annex; the consequence is O4 |
| 2026-10-20 | Found while documenting P5 | **Plan limits bound self-hosted servers.** Every org is created `free`, and nothing exempted a server that sells no plans. P1's member cap, P3's session cap and P5's meeting cap would have reached self-hosters with the next self-host image (published by hand, last on 2026-10-12, so none did); the device cap always had. Fixed by `Core::plans_sold` (*Plans bind only where they are sold*), with an integration test per fence on a server without `saas` |
| 2026-10-20 | **Before**: the field harness on `hosted-20261019-e46da07`, which predates FR-115 | One throwaway Free org, owned by the vmtest admin and listed in `growth_exclusions`; agents enrolled through the API with no daemon behind them; members past the owner are membership rows with no account. **AC1**: the 4th device refused, *"3 of 3 devices used"*. **AC2**: the 11th member **added** in `warn` and in `off`. **AC6**: two sessions requested 1 s apart, **both** created. **AC9**: a call backdated to 61 minutes still `in_progress` after 75 s, with no event. **AC5**: the old ladder on `/` and `/pricing` ("3 devices", "$8 /user/mo", no commercial-use line). Each AC fails, as it should on a deploy without FR-115 |
| 2026-10-20 | **After**: the same harness on `hosted-20261020-9776afb`, promoted 09:32Z | **AC1**: 100 devices enrolled, the 101st refused, *"Device limit reached for the Free plan (100 of 100 devices used)"*. **AC2**: the 11th member refused in `warn` and in `off`, *"Members limit reached for the Free plan (10 of 10 members used)"*. **AC6**: the second session refused with `org_session_limit`, *"…vmtest admin is connected to fr115-field-001 right now…"*; the first session got no `rc:terminate`. **AC9**: a call backdated to 56 minutes was warned at 09:49:44Z (`cap_warned_call_id` set) and ended at 09:53:44Z, 60 min 4 s after its start, with `room:call_ended {reason: plan_limit}` |
| 2026-10-20 | Found by AC5 on prod | **Annual on sale where nothing is.** `/api/stripe/plans` listed Free with a `year` price of $0, and every page reads a `year` entry as "annual is on sale". The billing page showed an *Annual · 2 months free* toggle, and the Free card on `/` and `/pricing` read *"or $0 per user per year (two months free)"*. These were AC5's only failures. Fixed by #2603 in the server (`get_plans`) and, defensively, in the UI. Also learned: a guest's `/pricing` is the static page, whose Free card says "Free for commercial use" as its first feature and has no chip |
| 2026-10-20 | Stripe **test mode** (#2604), test Prices on their own products | **AC3**: four real Checkout Sessions (Pro/Business × month/year × USD/EUR), each with quantity = 3 seats, the right Price and currency, and `amount_total` = 3 × the unit price. **AC4**: on a real subscription paid by the test card, a member joining moved the quantity from 2 to 3 with a proration charge, and leaving moved it back with a credit. Stripe's own subscription events, delivered as Stripe signs them, set plan, seats, interval and currency. **AC3 end to end**: our checkout opened a Sandbox Checkout page (*"Qty 3, €24.00"*), a real browser paid it with the test card, and Stripe's `checkout.session.completed` put the org on Pro with 3 seats, monthly, EUR. The invoice showed €24.00 paid. Everything created in Stripe was deleted afterwards |
| 2026-10-20 | **AC9 in real time**, on `hosted-20261020-9776afb` | A meeting in the field org with one participant joined over a live socket, as the SPA joins, started 09:55:54Z. `room:call_ending_soon` reached the client at 10:50:55Z (55:00.3, `ends_at` 10:55:54.743Z), and `room:call_ended {reason: plan_limit, max_minutes: 60, plan: free}` at 10:55:55Z (60:00.3). Afterwards the field org was cleaned up: the 9 filler memberships deleted, the 100 devices deleted through the API, and the org archived. It stays in `growth_exclusions` |
| 2026-10-20 | #2603 promoted (`hosted-20261020-d2eae7e`, 13:54Z), AC5 re-checked, **P6 sent** | Free lists only `month`. Every AC5 check passes on the static home, `/pricing` and the billing page: $8 / $16 per user per month, Free allows commercial use, no yearly line on Free, no Annual toggle, no €. AC5 stays unticked until O1 puts annual and EUR on sale. The announcement went to every real user at 13:55Z. SendGrid accepted every message, and internal, test and unverified accounts were excluded (counts in the private annex) |
| 2026-10-20 | **AC10, the orphaned orgs deleted** (O5, operator's decision) | The 62 ids came from the P0-ops export, and each was re-checked as a tombstoned org with no owner account before anything ran. Every collection was scanned for references to them or their rooms (as ObjectId or hex). There were 617 documents in 5 collections: orgs, memberships, rooms, room members and roles. No other collection referenced them. They were exported, and the export was verified (617 = 617) before the delete, which required that exact count. 0 documents are left. Prod holds 16 orgs and no tombstones. The exports stay on the ops host until the operator says otherwise |
| 2026-10-20 | **O1 live, and AC5 whole** | Live Stripe, on the operator's go (0 live subscriptions at the time): both monthly Prices gained an EUR option at the USD number, and annual Prices were created on the same products at $80 / €80 and $160 / €160 per seat per year. The prod ConfigMap got the two annual ids and `MESHHARBOR__STRIPE__CURRENCIES=usd,eur` (deploy repo), followed by a rollout restart (14:19Z). **AC5**: the static home (`/pricing` and `/landing` 301 to it) shows *"$8 / €8 per user / month · or $80 / €80 per user per year (two months free)"* and the Business pair. Free stays *"$0 forever"* and says it allows commercial use. The billing page, in a `de-DE` browser, shows the Monthly/Annual and USD/EUR toggles, €8 / €16 per user per month, and €80 / €160 per user per year with *"two months free"* |
| 2026-10-21 | **P4a-2 on the PoPs**: `derp-relay` from `hosted-20261020-247e017`, one PoP at a time, us-east first as the canary (06:08–06:11Z) | On all four, a garbage `POST /stats` went from 405 to **401**, and `/stats` gained `"allowance":{"networks":0,"age_s":null,…}`. The API's poller read every PoP through the swap: `stats_relay` got all 10 samples after it. Each PoP keeps its old binary for rollback. Every PoP had 0 DERP registrations, so no live frame crossed the new forward path here; the candidate check below covers the agent's side |
| 2026-10-21 | **0.4.149's candidate over DERP** (release-agent run 39586854858): the FR-115 gate before the tag | A kept vmtest cell paired with the anchor, `overlay_direct=false`. On 0.4.149: `relay`/`derp`, `roomler why` reading `relay:derp`, 20/20 pings out and 10/10 back. The same procedure on 0.4.148 gave the identical result, the control showing the rig really forces DERP. The release session accepted it, and 0.4.149 was released at 11:29Z |
| 2026-10-21 | **Promoted `hosted-20261021-adbdadc`** (12:46Z), the operator's go | Pods Ready at 12:51Z, `/health` 200, all 24 agents back (0 missing). **The API's set reaches every PoP**: `age_s` went from `null` before the roll to 14–15 s on all four after it, and refreshes on every poll. `networks` stays 0, as it should with the switch off |
| 2026-10-21 | **P3b on**: `rc.session_slots` (deploy `596782e`, rollout restart 13:05Z), the operator's go. The harness's `ac6s` arm: a throwaway Free org, two simulated agents, two controller sockets | **Red, switch off (13:03Z):** the second same-org session was refused by P3's hub count (`org_session_limit`, *"…vmtest admin is connected to fr115-field-001 right now…"*), `rc_slot_full_total` stayed 0, and Redis held no slot key. **Green, switch on (13:06Z):** the same refusal in the same words, but **`rc_slot_full_total` went 0 → 1**, and the org's slot set held exactly session 1 during the hold. In both runs session 1 got no `rc:terminate`, and session 2 opened once session 1 ended. Fleet: 0 agents missing after the restart. AC6's cross-org half is still owed: it needs an account outside the device's org |
| 2026-10-21 | **AC6's cross-org half**, through FR-52's real external path, with `rc.session_slots` on (15:09Z). One outsider account, seeded in the DB on the operator's instruction (a fake `.invalid` email, excluded from growth, deleted after the run). Three throwaway Free orgs of the vmtest admin: V holds the devices, and the outsider joins X1 and X2. The simulated devices answer the blind relay | **No org:** a second concurrent external session was refused `session_limit` (*"Without an organization, an account runs one remote session at a time, and you are connected to fr115-field-001 right now…"*), and it opened once the first ended. **Cross-org:** while the admin's same-org session held X1's slot, the outsider's external session charged to X1 was refused `session_limit` in X1's own words (*"…vmtest admin is connected to fr115-x1-001 right now…"*). The control, charged to X2, opened, and the X1 one opened once the admin's session ended. `rc_slot_full_total` on the device org's pod rose by exactly the two refusals, and the org's `external_rc_audit` agrees. A first run misread every outcome (a same-millisecond `>=` time filter in the harness); the waits are index-based now. **AC6 ticked** |
| 2026-10-21 | **The relay allowance switched on** (deploy `f5940b7`, rollout restart 21:23Z), the operator's go. Then **AC7** on a throwaway Free org: two kept vmtest cells re-enrolled into it, one with `overlay_direct=false` so the pair rides DERP, and an 8 MiB download over the overlay. A single synthetic 11 GB `derp_bytes` ledger row put the org over its 10 GB, and removing that row was what lifted the throttle | **Before the switch:** 0 orgs over their allowance (the highest at 3.5 %), so it held nobody. **Under the allowance:** DERP, 0.45 s (≈149 Mbit/s). **Over it:** still DERP and still connected, **77.5 s = 866 kbit/s**, the Free bucket of 1 Mbit/s less TCP and WireGuard overhead. The set (one network at 125,000 B/s) reached all four PoPs, and the analytics read *throttled*. **Direct, while over:** 0.067 s, and the org's `derp_bytes` grew by only 1,826 B of handshake and disco, not the 8,388,608 B transferred. **Row removed:** the set cleared within 31 s, and DERP ran at 0.46 s again. Still owed for AC7: the org-relay clause (zero by construction, not yet field-run or named in a test). Still owed for O3: its usability items |
