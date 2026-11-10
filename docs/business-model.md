# Business model

How MeshHarbor makes money, what it costs to run, and which of those numbers are
measured rather than assumed. This is the document the pricing decisions are made
*from* — if a tier changes, the argument for it belongs here.

Companion documents: [`LICENSING.md`](../LICENSING.md) (what the split permits),
[`COMMERCIAL.md`](../COMMERCIAL.md) (the exception we sell), and the FRs behind
each mechanism — [FR-24](fr/FR-24-licensing-split.md) licensing,
[FR-32](fr/FR-32-plan-limit-enforcement.md) enforcement,
[FR-20](fr/FR-20-per-tenant-relay-cost-metering.md) metering.

---

## 1. Three revenue mechanisms, one product

There is exactly one codebase. Money arrives three ways.

| | Who pays | For what | Status |
|---|---|---|---|
| **Cloud subscription** | orgs on `meshharbor.itachi.fans` | seats + capacity above the free tier | live (Stripe) |
| **AGPL exception** | a company embedding or re-hosting the control plane in a proprietary product | permission the AGPL withholds | mechanism live, unpriced |
| **Self-hosting** | nobody | — | free, unlimited, forever |

Self-hosting being free is not charity and not a funnel trick: it is the
distribution channel. The product asks people to run a privileged daemon that can
see their screen, and for an unknown vendor **auditable source is the only trust
substitute available**. Anything that weakens it — telemetry from self-hosted
installs, a crippled community build, a licence key check — costs more than it
could earn. See [`LICENSING.md`](../LICENSING.md).

### Why the licence is a revenue mechanism and not a moat

FR-24 measured this rather than assuming it: **AGPL covers ~37% of the codebase
and 0% of the differentiated code.** `crates/api` links `tunnel-core`
unconditionally, so the carrier cascade is shared and must take the permissive
licence; the encoder cascade is agent-side and permissive too.

So the AGPL does not protect the crown jewels, and we do not claim it does. What
it does is make **hosting the control plane commercially unattractive without a
licence** — and the buyer of that licence is a procurement department reacting to
the letters "AGPL", not an engineer reading the dependency graph. That is the
mechanism. It works at 37% coverage.

---

## 2. What actually costs money

Almost nothing scales with usage. Two things do.

| Cost driver | Scales with | Metered? |
|---|---|---|
| **Relay traffic** (DERP + TURN) | bytes that could not go peer-to-peer | ✅ `derp_bytes` · `turn_bytes` **deliberately not collected** — coturn 4.17.2 exposes no per-user label, and per-tenant TURN buys nothing until a tenant relays material volume (FR-20 P3) |
| **SFU conferencing** | participant-seconds | ✅ `sfu_participant_seconds` |
| Object storage | GB stored | not yet metered |
| Everything else | ~flat | n/a |

**Direct peer-to-peer sessions cost the control plane kilobytes of signalling.**
A remote-desktop session that finds a direct carrier moves its pixels between the
two endpoints and never touches us. This is why the free tier can be generous
about devices and sessions, and it is why:

> ⚠️ **Direct traffic is never metered and never capped.** FR-20 carries this as
> its load-bearing acceptance test — *a direct-carrier transfer must write zero
> relay bytes*. Metering it would bill users for the exact outcome the whole
> NAT-traversal programme exists to produce, and would make our incentives point
> the wrong way.

### The relayed fraction is the number to watch

The share of traffic that falls back to a relay is simultaneously:

- **the cost driver** — it is the only traffic we pay for; and
- **a product-quality alarm** — it rises when NAT traversal regresses.

It is on `/observability`. A jump there is a bug report before it is a bill.

---

## 3. What the meter has measured so far

First real data, 2026-08-30 (metering went live the same week — this is a
datapoint, **not** a basis for pricing):

| | |
|---|---|
| `derp_bytes`, 24 h | 1 765 944 520 B (~1.77 GB) across **2 tenants** |
| `sfu_participant_seconds`, 24 h | 3 930 s across 1 tenant |
| Regional PoP fleet | **~idle** — all five regions at `tx_mbps` ≈ 0.001 |

Two things follow immediately:

1. **Relay volume today is trivial**, and one tenant is essentially all of it.
   Nothing in the current tier ladder is being tested by real cost.
2. **The regional PoPs are carrying almost nothing** — the fleet's DERP rides the
   API pods. That is a fixed cost being paid for capacity nobody uses yet, and it
   is a question for the infrastructure budget rather than the price list.

⚠️ **Do not price from this.** The stated sequence is measure first, then reshape
(§5). One day of data from two tenants, one of them ours, decides nothing.

### Seven weeks later (2026-10-19)

What FR-115 reshaped the ladder on — 30 days of the whole fleet, which is still
mostly our own (stress lanes, forced-relay runs, corporate laptops that sit on the
DERP floor by design), so these are a **heavy user's** numbers, not a typical one's:

| Cost driver | 30 days | At `relay-costs.toml` prices |
|---|---|---|
| Direct P2P | 373 remote-session hours; 94 % of sessions with a recorded carrier went direct | €0 by construction |
| `derp_bytes` | ≈ 30 GB (79 GB since 2026-08-30); median day 0.3 GB | ≈ €0.30 |
| coturn (fleet total, not per tenant) | ≤ ≈ 950 GB host egress on the central coturn workers; 41 allocations on average | ≤ ≈ €9.50 |
| `sfu_participant_seconds` | ≈ 0 | ≈ €0 |

The whole product's variable cost is about **€10 a month**, and the largest part is the
one relay no tenant can be charged for yet (coturn, FR-20 P3 deferred). Devices,
direct traffic and chat cost nothing measurable. That is what the FR-115 ladder below
is built on: give away what costs nothing, cap what does.

---

## 4. The ladder today

**FR-115** ([#2557](https://github.com/jk-zhang-meta/MeshHarbor/issues/2557)), operator
decisions 2026-10-19. Paid plans are **per seat** (a seat is a member who accepted),
monthly or **annual at two months free**, in **USD or EUR** at the same number. Plan
ids (`free`/`pro`/`business`) are stored in tenant documents and matched in the
webhook, so **renaming one is a migration**, not a copy change.

| | Free | Pro | Business |
|---|---|---|---|
| Price per seat | 0, **commercial use allowed** | $8 / €8 a month · $80 / €80 a year | $16 / €16 a month · $160 / €160 a year |
| Users | 10, enforced | per seat | per seat |
| Devices · tunnel clients | 100 · 100 | 1,000 · 1,000 | 5,000 · 5,000 |
| MagicDNS | ✅ | ✅ | ✅ |
| Exit nodes | from FR-115 P4d | ✅ | ✅ |
| Concurrent remote sessions | 1 per org | 1 per seat | ∞ (fair use) |
| Relay (DERP + TURN) at full speed | 10 GB / month | 25 GB per seat | 100 GB per seat |
| Meetings | 10 people, 60 minutes | 50 people | 100 people + recordings |
| Storage | 1 GB | 10 GB per seat | 50 GB per seat |
| Chat channels, history | unlimited | unlimited | unlimited |
| Overlay mesh, own relays (FR-19) | ✅ | ✅ | ✅ |

The code is `Plan::limits_for(seats)` (`crates/db/src/models/tenant.rs`): the
published matrix is one seat's numbers, and an org's own limits scale by the seats its
subscription bills (`Tenant::billed_seats`).

Notes that matter more than the numbers:

- **The mesh is on every tier, including Free**, and since FR-115 so is every mesh
  feature that costs nothing (MagicDNS). Exit nodes join Free once the relay throttle
  exists: an exit whose path falls to DERP is the one way Free could cost real money.
- **Free fences by objective limits, never by "personal use" detection** — one
  concurrent remote session, ten users, no support sessions to other orgs (FR-52).
  The remote-desktop vendors fence free with commercial-use detection; we allow
  commercial use outright and say so.
- `Enterprise` exists in the `Plan` enum with Business's limits and price and is
  never returned by `get_plans()`. It is still a **placeholder, not a tier.**
- Free's `video_max_participants` was `0` until FR-32 and enforced nowhere, so
  Free tenants have always held calls. It went to **4**, and to **10** with a
  60-minute meeting in FR-115 — enforcing `0` would have removed a capability
  people already use, which is a different act from holding a line. Both fences
  hold in every mode since FR-115 P5; the census before they shipped found no
  meeting either would have changed.
- ⚠️ Before FR-115, checkout sold **one unit per org** whatever its size while the
  site said "per user", and a plan switch ran a second checkout that started a
  second subscription. Both are fixed: checkout bills `quantity = seats`, a
  15-minute reconcile keeps it equal to the member count with proration, and a plan
  change moves the existing subscription's item (`POST /api/stripe/change-plan`).

### Enforcement posture

Fourteen limits, one decision point (`services::quota`), three modes per tenant:
`Off` → `Warn` (record the denial, allow the request) → `Enforce`.

⚠️ **The mode reaches only the limits still being staged.** The *established* ones
refuse in every mode, `Off` included (`Limit::is_established`): devices and tunnel
clients (enforced before FR-32), members (FR-115 D2), concurrent remote sessions (FR-115
P3), and Free's two meeting fences, participants and meeting length (FR-115 P5). Every new
org starts in `Warn`, so a fence that `Warn` softened would not be one.

⚠️ **Grandfather before enforcing.** `/plan-compliance` answers *"who would break
if I turned this on?"* as a **snapshot**, not from denial logs — a tenant sitting
at 40 members on a 10-member plan that nobody adds to this month emits no denials
at all and would be flipped straight into a wall.

**All of this binds only where plans are sold.** A self-hosted server is built
without the `saas` module, sells no plans, and holds no org to any limit. An org
there is `free` in name only (`Core::plans_sold`, FR-115).

---

## 5. The sequence, and why this order

The originating strategy brief proposed a new EUR ladder up front. That was
rejected: it set prices before anything measured what a tenant costs, while
admitting the numbers were not researched against our cost base.

| | | status |
|---|---|---|
| **P1** | Make the advertised limits true — enforce all fourteen, log every denial | ✅ FR-32 |
| **P2** | Meter the real cost drivers per tenant; expose, don't bill | ✅ FR-20 |
| **P3** | **Reshape tiers on measured cost** — and only then decide currency, the free-device cap, and whether an MSP tier exists | ✅ decided 2026-10-19 — [FR-115](fr/FR-115-pricing-reshape.md), shipping in phases |
| **P4** | Offline Ed25519 licence keys for self-hosted Enterprise | ⬜ when someone asks to buy one |

Denials from P1 are the other half of the input: they are the **best
upgrade-intent signal available**, and they come free with enforcement.

### What P3 has to answer

- **Is per-user the right metric?** TeamViewer/ScreenConnect/AnyDesk price per
  *concurrent technician*, because three humans support five hundred machines.
  Our device caps (30/300) become the binding constraint for exactly the customer
  who would pay most. `max_concurrent_sessions` already exists and is enforced —
  the metric is half-built.
- **Is Free too tight at 3 devices?** Self-hosting is unlimited and free, so the
  cloud free tier's only job is converting people who would rather not self-host.
  Three devices may be too few to fall in love with a mesh product.
- **Does conferencing stay?** It is the one component with genuinely high
  marginal cost and the least differentiation.
- **USD or EUR**, and whether `Enterprise` becomes real or is deleted.

**How FR-115 answered them:** per seat for the bundle, with **concurrent remote
sessions** as the fence on Free and a per-seat allowance on Pro (the metric the
remote-desktop vendors sell, without making three technicians buy five hundred
seats); Free at **100 devices**; conferencing **stays**, fenced on Free by meeting
length (the meeting vendors' own fence); **both** currencies; `Enterprise` still a
placeholder. An MSP tier waits for an MSP to ask.

---

## 6. Rules that do not change with the price list

1. **Self-hosted never phones home.** No licence check, no telemetry, no
   activation. Currently true by construction; it must stay a design property.
2. **Never meter or cap direct peer-to-peer.**
3. **Bill only on what the server or its own relays measured.** `tunnel_audit`'s
   byte columns are reported by the client endpoint — a claim by a host we do not
   control. They inform analytics and never the ledger.
4. **Never kill a live session over billing.** Past a relay allowance, relayed
   traffic is **throttled, never refused** (FR-115 D4, which replaced "refused"):
   for a host behind symmetric NAT or a full-tunnel VPN the relay is the only path,
   so refusing it would mean the product stops working. Direct connections and an
   org's own relays are never counted. A refused *new* session (a concurrency cap)
   names what holds the slot. Someone debugging a production box at 2 a.m. must be
   told *why*.
5. **Failed payment degrades, never deletes.** Grace period → Free entitlements.
   Devices and org data survive.
6. **Nothing is removed from the community edition** to make a paid tier look
   better. That inverts the distribution strategy.

---

## 7. Open decisions

| # | Decision | Blocked on |
|---|---|---|
| ~~1~~ | ~~Tier reshape — metric, prices, currency~~ — **decided 2026-10-19 in [FR-115](fr/FR-115-pricing-reshape.md)**: per seat, USD and EUR, annual at two months free, Free at 100 devices and 10 users with commercial use allowed | — |
| 2 | Price the AGPL exception | first real enquiry |
| 3 | `Enterprise`: make real or delete | #1 |
| ~~4~~ | ~~HEVC patent pool~~ — **decided 2026-09-01: HEVC stays ON by default.** Only vendor hardware encoders ship (`*_nvenc`/`*_qsv`/`*_amf`/`*_videotoolbox`); we distribute no HEVC implementation, and the vendor licenses the silicon. Reasoning + the three things that keep it true in [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md) | — |
| 5 | Retire or right-size the idle regional PoP fleet | infra budget review |
| 6 | Meter object storage | whether it ever becomes material |

---

*Numbers in §3 are measurements with a date attached. Numbers in §4 are what the
code does today. Everything in §5 is a plan, and plans in this document are
expected to be wrong until §3 has enough data to correct them.*
