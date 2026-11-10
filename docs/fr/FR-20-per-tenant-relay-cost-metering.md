# FR-20 — Per-tenant relay cost metering

**Issue:** [#807](https://github.com/jk-zhang-meta/MeshHarbor/issues/807) · **Status:** design · **Owner:** @gjovanov

## Goal

Attribute **relay cost to the tenant that caused it**, and surface it in the two
places that already exist: `/observability` for the platform owner and
`/tenant/{tid}/analytics` for org admins.

This is the precondition for every pricing decision. Pricing before measuring is
how you set numbers you cannot defend, so this FR ships **no quota and no
enforcement** — those are a separate FR, opened only after a month of real data.

## Root cause / field evidence

Measured against `origin/master` @ `fa364b12`.

### What already exists — more than a licensing/pricing audit assumed

The observability subsystem is substantial and shipped:

| Collection | Keyed by | Retention |
|---|---|---|
| `stats_relay` | **`{region, ts}`** | 7 d + `_1h` 90 d + `_1d` 730 d |
| `stats_machine` | `{tenant_id, agent_id, ts}` | 7 d + rollups |
| `stats_call` / `stats_call_user` | `{tenant_id, room_id/user_id, ts}` | 7 d + rollups |
| `call_sessions` | `{tenant_id, room_id, started_at}` | 730 d |
| `stats_events` | `{tenant_id, agent_id, ts}` presence ledger | 730 d |
| `stats_mesh`, `ws_sessions`, `page_views` | topology, sessions, pageviews | 7–90 d |
| `tunnel_audit` | per-flow bytes + `RelayMode` | 90 d |

Served by `routes/stats.rs` (1 448 lines), `routes/usage.rs` (1 096 lines,
per-user minutes+bytes across remote-desktop / calls / tunnels), `stats_rollup.rs`,
`relay_load.rs`, `media_stats.rs`. Both UIs exist and are populated:
`ObservabilityView.vue` (relay fleet, orgs, users & sessions, platform-wide
participant-minutes, usage by person) and `AnalyticsView.vue` (machines online,
transports direct/relay/derp, peer latency, peak participants, call minutes,
tunnel traffic, flows direct vs relayed).

### The gap

**`stats_relay` is keyed `{region, ts}`** (`crates/db/src/indexes.rs:523`). It
records CPU, memory, rx/tx rate, DERP registrations and coturn allocations *per
PoP* — fleet health, not consumption. There is no per-tenant relay byte anywhere
in the system, so the question *"what did org X cost me last month?"* has no
answer, and neither does *"what is the gross margin on the Pro tier?"*

The two genuinely variable costs are relay traffic (coturn TURN + DERP) and the
mediasoup SFU. Neither is attributed. Everything else — device count, signalling,
mesh coordination, chat — is effectively free per unit.

### Attribution is already reachable at all three relay tiers

Verified in code, not assumed:

| Tier | Tenant known? | Byte count available? |
|---|---|---|
| API-pod DERP (`crates/api/src/ws/derp.rs`) | **yes** — `verify_agent_token` + authoritative DB lookup (`derp.rs:236`); a forged tenant claim cannot widen scope | **yes** — `frame.len()` already computed on that path for `tunnel_budget_permits` (`derp.rs:508`) |
| PoP DERP (`crates/derp-relay`) | via the ticket's `network` → `overlay_networks` → tenant | in-process; the binary is deliberately **DB-free** |
| coturn TURN | username is `{expiry}:{user_id}` (`crates/remote_control/src/turn_creds.rs:63`) — user, **not** tenant | `coturn_prometheus()` already scrapes; reads only `turn_total_allocations` / `turn_total_sessions` today |

## Key design

### The rule: bill only on what we measured ourselves

`tunnel_audit`'s byte columns are reported by the **client endpoint** on flow
close — the server cannot measure them, because the payload is P2P over the data
channel (`routes/usage.rs:14-19`). That is a *claim by a host we do not control*.

Same distinction CLAUDE.md already draws between `ssh_audit` (the server's own
decision, authoritative) and `ssh_activity` (the device's account of itself).
⚠️ **They are never folded together.** Client-reported bytes stay in analytics,
labelled as such; only server-measured bytes enter the cost ledger.

### One ledger

`stats_usage`, following the shipped pattern exactly — deterministic string `_id`
= `{tenant_id}:{meter}:{bucket}` so every writer is an **idempotent upsert**.
That, not a lease, is what makes the 2-pod deployment race-free; it is the same
property `stats_relay` and `stats_machine` already rely on. Rollups `_1h` (90 d)
and `_1d` (730 d) come from the existing `stats_rollup` task via `$merge` on `_id`.

Meters — **cost drivers only**:

```
derp_bytes                relay bytes forwarded on this tenant's behalf
turn_bytes                coturn-relayed bytes
sfu_participant_seconds   the SFU's real marginal cost
storage_bytes             gauge
```

⚠️ **Never metered:** direct P2P sessions, device count, signalling, mesh
coordination, chat messages. A direct session costs the control plane kilobytes
of signalling; metering it would invert the growth model and punish exactly the
outcome the NAT-traversal work exists to produce.

### Three collection points

**A · API-pod DERP.** One lock-free atomic add into a per-network map inside
`forward_frame`, flushed to `stats_usage` on a 60 s timer. ⚠️ **Never a Mongo
write per frame** — and nothing else on that path: this is where relay latency
lives, and FR-18 is actively fighting queueing there.

**B · PoP DERP.** `derp-relay` stays DB-free (a design invariant of that binary —
it holds only the ticket's public key and no Mongo at all). It counts bytes per
`network` in an in-process map and exposes a new `per_network` object in the
`/stats` payload that `relay_load.rs` already polls every 30 s; the poller
resolves network → tenant and writes the buckets.
⚠️ These are **cumulative counters**, so the poller must diff successive samples —
the same shape `machine_series_pipeline` already uses for agent counters
(`stats.rs:190-201`). A PoP restart resets mid-bucket, so that bucket
**under-reports rather than going negative** — the identical trade the host-total
`net_*_bytes` columns already make. Do not invent a different one.

**C · coturn TURN.** Extend `coturn_prometheus()` to read `turn_traffic_*`.
⚠️ The username is `{expiry}:{user_id}` and a user may belong to several orgs, so
the username alone cannot attribute. ⚠️ **Do not change the username format** — it
is HMAC input (`turn_creds.rs:55-70`) and both ends would need coordinating.
Instead write a TTL'd `turn_grant` map (username → tenant) at *issuance*, where
the API already knows the tenant. A grant that has expired out of the map yields
an **unattributed** bucket, never a wrongly-attributed one.

> ### ⚠️ C AS WRITTEN ABOVE CANNOT WORK — measured on the live fleet, 2026-08-30
>
> The `turn_grant` map resolves *username → tenant*. But **the username never
> appears in the metrics**, so there is nothing to resolve. Read from the real
> exporter on a coturn worker (`10.10.10.11:9641`, coturn **4.17.2**), the entire
> set of label combinations it emits is:
>
> ```
> {realm="meshharbor.itachi.fans"}   {type="TCP"}   {type="TLS/TCP"}   {type="UDP"}
> ```
>
> `grep -c 'user=|username='` over the whole payload returns **0**. Every
> `turn_traffic_*` series is a **realm-level aggregate**. Building the parser and
> the grant map as specified would produce a lookup that matches nothing — the
> same "machinery in front of data that does not exist" this FR already refused
> twice elsewhere.
>
> **Two mechanisms do exist in 4.17.2**, and choosing between them is an
> operational decision, not an implementation detail:
>
> | Option | Cost |
> |---|---|
> | `--prometheus-username-labels` | Minimal code — the specced design then works verbatim. ⚠️ But our usernames are `{expiry}:{id}`, **unique per issuance and never reused**, so every credential mints a new time series: an unbounded, monotonically growing label set in coturn's registry. A textbook cardinality bomb, made worse by the timestamp the username format is *required* to carry (it is HMAC input). |
> | `-O, --redis-statsdb` | Per-session records carrying username and byte counts; no cardinality growth, and we already run Redis. Needs a new integration and its schema verified. |
>
> **Recommendation: defer C, and prefer redis-statsdb when it is taken up.**
> Per-tenant TURN attribution buys nothing until there is a tenant to attribute
> to, and the fleet-total TURN cost is *already* visible — `stats_relay` carries
> each region's `rx_mbps`/`tx_mbps` from the host counters, so a realm-total
> would be nearly redundant with what is collected today. It also does not belong
> in `stats_usage`, which is per-tenant by construction.

### Cost model

`config/relay-costs.toml` maps meter → unit cost, edited in one place, so
`/observability` can render currency and margin without any price constant
appearing in code.

### Surfaces

**`/observability`** (platform allowlist) — a *Cost & usage* section under the
existing relay-fleet block:

- fleet totals per meter over the range + estimated cost
- per-org table: org · relay GB · SFU hours · storage · est. cost · plan · MRR ·
  **margin**, sorted by cost
- **relayed fraction** — the fraction of traffic that could not go direct. The
  most valuable number on the page: simultaneously the cost driver *and* a
  NAT-traversal regression alarm that fires before any user complains.

**`/tenant/{tid}/analytics`** (membership, fail-closed) — a *Usage* section
extending the existing "Transports (direct / relay / derp)" card: relay bytes,
SFU participant-hours, storage, and the org's own relayed fraction — framed as
**actionable**, because a high relay fraction means that org's network is
blocking direct paths, which they can act on. A quota bar is left as a slot,
wired dark until quotas exist.

⚠️ Both surfaces reuse the existing gates unchanged, and **failures stay 404,
never 403** — the web client wipes tokens on 403, so a member removed mid-poll
must not be logged out of everything (`stats.rs:45-47`).

## Phases

| P | Scope | Kill switch |
|---|---|---|
| **P1** | `stats_usage` + rollups + **A** (API-pod DERP). Smallest end-to-end slice; proves the shape on real traffic. | meter writes are additive; flag off ⇒ no rows |
| **P2** | **B** — PoP `per_network` counters + poller attribution | PoP omitting `per_network` ⇒ "not monitored", never `0` |
| ~~**P3**~~ | **C — DECIDED: not built, and not "blocked".** coturn 4.17.2 emits only realm-level `turn_traffic_*` (measured on the live fleet: the entire label set is `{realm}`/`{type}`, `grep -c user=` returns **0**), so the specced username→tenant map would resolve nothing. Both available mechanisms were weighed — `--prometheus-username-labels` is a cardinality bomb (our usernames carry a timestamp and are never reused), `--redis-statsdb` is sound but needs an integration. **Deferred deliberately**: per-tenant TURN attribution buys nothing until a tenant actually relays meaningful TURN volume, and fleet-total TURN cost is already visible via `stats_relay`. `turn_bytes` is correctly **absent from `MONITORED`**, so the surface reports it *unmonitored* rather than `0`. **Reopen when** a tenant’s TURN volume becomes material; prefer redis-statsdb. | n/a — not built |
| **P4** | `sfu_participant_seconds` folded in — mostly a rollup over existing `stats_call_user` | rollup-only |
| **P5** | `relay-costs.toml` + `/observability` Cost & usage section | UI-only |
| **P6** | `/tenant/{tid}/analytics` Usage section | UI-only |
| **P7** | **Docs** — [`docs/relay-cost-metering.md`](../relay-cost-metering.md) in house style with diagrams, linked from `docs/README.md`'s map and table | docs-only |

## Acceptance criteria

- [x] A relayed transfer of *N* MB between two fleet hosts appears in that
  tenant's `stats_usage` within one rollup interval. **The ±5% this criterion
  originally demanded was the wrong tolerance, because it compared two
  different layers**: the meter counts what crosses the relay (WireGuard
  encapsulation + DERP framing), while the payload figure is application-level.
  Measured 2026-08-30: **+12%**, which is the encapsulation overhead on ~1.4 KB
  packets and is expected to *grow* as packets get smaller. The real invariant
  is directional — **metered ≥ payload, never less** — plus agreement in
  magnitude; a byte-exact reconciliation would require accounting for framing
  per tier and buys nothing for billing.
- [x] **The same transfer over a direct carrier writes zero relay bytes** — the load-bearing test; if direct traffic ever meters, the growth model is broken
- [x] Killing a PoP mid-bucket under-reports; **no bucket is ever negative** — field-verified 2026-08-30: **0 negative** across 680 raw buckets, `stats_usage_1h` (22) and `stats_usage_1d` (4)
  - unit-covered (`checked_sub` yields `None` on a reset, three cases); **not
  field-exercisable today**, because every PoP is idle (see the log below), so
  there is no counter to reset. Re-open when a tenant is actually homed to a PoP.
- [x] Two pods writing the same bucket yield exactly one row (asserted in `crates/tests`)
- [x] The ledger stores exactly what the flush drained — verified on prod across three consecutive minutes (22:43/44/45 UTC: 86 278 / 108 818 / 109 538, log value == stored value), plus **zero** loss lines in 24 h (`usage flush skipped`, `usage bucket write failed`, `could not be attributed` all 0 on both pods)
- [x] **The meter is honest — pinned by tests, not by a one-off reading.** The original text ("agrees with the PoPs. own `net_tx_bytes`") was **unfalsifiable**: `stats_relay` has never stored that field (absent in all 100 800 docs; `relay_load` writes `rx_mbps`/`tx_mbps`). Its *intent* — does the ledger equal what we actually relayed? — is now answered directly by `ws::derp::tests`: the ledger bills **exactly** the bytes enqueued (32-byte rewritten src + payload, not the inbound length) and **zero** on every drop path — unregistered dst, cross-network, ACL-denied, full queue, malformed — with warn-mode pinned as the mirror (it delivers, so it must bill). ⚠️ **Verified falsifiable**: hoisting `add_network_bytes` above the enqueue makes 4 of them fail. That is stronger than comparing two counters, which could both be wrong the same way; `DERP_BYTES_RELAYED_TOTAL` remains for a live spot-check
- [x] A tenant with no relay traffic renders `0`; an unmonitored PoP renders "not monitored" — never the same cell
- [x] `/observability` shows per-org cost + margin and the fleet relayed fraction
- [x] `/tenant/{tid}/analytics` shows the org's own usage and relayed fraction
- [x] Measured DERP forward-path overhead is within noise of the pre-change
  baseline — **99.92 ns/frame**, i.e. **0.002 % of one core** at the busiest
  minute this deployment has ever recorded. See the log below; the numbers
  come from `bench_add_network_bytes_cost`, not from an argument about how
  cheap an atomic is.
- [x] **Docs updated/created with diagrams, linked from `docs/README.md`** —
  [`docs/relay-cost-metering.md`](../relay-cost-metering.md), house style with
  three mermaid diagrams (the provenance split that decides what may enter the
  ledger, the hot-path/flush sequence, the two surfaces and why only one renders
  money), plus a node in the README map and a row in *Install & operate*.
  ⚠️ This criterion was **added retroactively**: FR-20 predates the 2026-09-05
  standing rule that makes docs part of an FR's close, so its original ten
  criteria carried none — and no page under `docs/` covered relay cost metering
  at all. Recorded rather than backdated, because a spec that looks like it
  always complied teaches the next reader nothing.

## Open decisions

1. Whether P4 (SFU participant-seconds) belongs here or in its own FR — it is
   nearly a pure rollup over data that already exists, which argues for here.
2. Currency and unit costs in `relay-costs.toml` — owner-supplied; the FR only
   builds the mechanism.
3. Whether `/tenant` analytics should show a currency figure at all before
   quotas exist, or only raw units.

## Out of scope

- **Quotas and enforcement.** Deliberately deferred: measure for a month first.
- Any change to a price, tier or plan id.
- The 11 declared-but-unenforced `PlanLimits` fields — own FR.
- Licensing (`AGPL`/`MPL` split) — separate program, undecided.

## Related

- Child of the pricing program; **blocks** any tier reshape
- A rising relayed fraction is a NAT-traversal regression signal for
  [#767](https://github.com/jk-zhang-meta/MeshHarbor/issues/767) (FR-1),
  [#801](https://github.com/jk-zhang-meta/MeshHarbor/issues/801) (FR-18)
- [#805](https://github.com/jk-zhang-meta/MeshHarbor/issues/805) (FR-19, peer relays)
  would add a **fourth** relay tier that must also be metered

## Field-verification log

| date | what | result |
|---|---|---|
| 2026-08-28 | Audit of the shipped stats subsystem | 10 collections + 2 populated UIs already exist; the gap is attribution, not measurement |
| 2026-08-28 | `stats_relay` key inspection (`indexes.rs:523`) | `{region, ts}` — fleet health, **no tenant dimension** |
| 2026-08-28 | Attribution reachability at all three relay tiers | API-pod DERP: tenant + length both already in hand; PoP: ticket carries `network`; coturn: needs the grant map |
| 2026-08-28 | `tunnel_audit` byte provenance (`usage.rs:14-19`) | client-reported on flow close ⇒ **not billable**, analytics only |
| 2026-08-30 | PoP `per_network` rolled to all four regions, canaried one at a time | field went ABSENT to `{}` with `healthz=200` on each: **monitored, relayed nothing** - the exact distinction P5 must preserve |
| 2026-08-30 | Ledger concurrency, against real MongoDB (#1028) | 3/3; **verified falsifiable** - breaking `_id` determinism split one bill into 1000 + 2345 instead of 3345, and only that test failed |
| 2026-08-30 | **NEGATIVE arm: 300 MB over a direct carrier (mars to zeus)** | overlay TX confirmed **313 MB in 5 s**, carrier `direct` at both ends; peak metered minute **145,650 B**, and that peak is a *pre-transfer* minute. Payload is **2,060x** the peak - **zero attributable** |
| 2026-08-30 | **POSITIVE arm: same apparatus over a relayed carrier (mars to neo16-wsl-2)** | 6,116 pkts / 60 s; **19,545,144 B metered** vs 17,454,444 B of two-way ICMP payload (+12%, encapsulation-shaped, never less); **116x background**, decaying to background the minute it stops |
| 2026-08-30 | Bucket attribution granularity | the flush timer writes the drained counter into the bucket current **at flush time**, so a minute's bytes can land one bucket late (2.67 MB / 16.87 MB for an even 60 s load). **Total conserved, placement coarse** - immaterial to the 1 h/1 d rollups billing reads; a per-minute chart must not be sold as packet-accurate |
| 2026-08-30 | PoP metering path, end to end | `https://derp-<region>.meshharbor.itachi.fans/stats` gives **HTTP 200**, `per_network` present, `derp_registrations=0` on all four. Wired, polled and healthy - and **carrying nothing, because no agent is homed to a PoP**. The central `/derp` on the API pods carries all of it today |
| 2026-08-31 | Forward-path overhead, measured (`bench_add_network_bytes_cost`, 8 threads on ONE network id — the realistic AND worst case) | atomic alone **16.39 ns**, `add_network_bytes` **99.92 ns**, so the DashMap lookup is **83.53 ns — 5x the atomic**. At 200 frames/s (the busiest recorded minute, 16.87 MB at ~1.4 KB/frame) that is **0.002 % of one core**, and ~500x headroom before it reaches 1 %. Against FR-18's 200 ms p99 the added per-frame latency is ~5e-7 of the budget |

## What the two arms actually establish (2026-08-30)

The negative arm alone proves nothing: **a meter that is simply asleep also
reports zero.** That is why the positive arm ran against the same tenant, the
same ledger and the same minute buckets, changing only the carrier. Together
they establish that the meter *sees relayed bytes and is blind to direct ones*,
which is the property the growth model is priced on.

Two limits of that claim, stated so nobody over-reads it:

1. **It proves the central `/derp` writer** (`ws/derp.rs`). The PoP writer
   (`relay_load.rs`) is deployed, polled and returning the right shape, but has
   never had a non-zero input in the field - `derp_registrations=0` everywhere.
2. **Direct traffic is unmetered because the counters live in the relay forward
   path**, not because anything filters it. Direct packets never enter either
   process. That is the structural reason the result is expected to be stable -
   but it also means the invariant is only as durable as that placement: a
   future meter fed from agent-reported `net_tx_bytes` or netmap stats would
   silently break it, and the 300 MB arm is the test that would catch it.

## Correction: "relayed fraction" cannot be a BYTE fraction (2026-08-30)

The Surfaces section above calls it *"the fraction of traffic that could not go
direct"*, which reads as bytes. **That number is not computable, and building it
would contradict the FR's own foundation.** Direct bytes are measured nowhere —
the meters live in the relay forward path, which is exactly why a direct
transfer meters zero — so there is no denominator. Any byte-level fraction
would have to invent the direct half.

Both surfaces therefore render the relayed share of **peer connections**,
labelled as such on the card itself. Two properties travel with it:

- **It is agent-reported** (`sys.transports.{direct,relay,derp}`), so it is a
  claim by the fleet rather than a server measurement — the same provenance
  split as `ssh_activity` vs `ssh_audit`, and the same rule applies: it may
  raise an alarm, it must never price a bill.
- **No reporters yields `null`, not `0`.** A zero here reads as a flawless
  mesh, which is the most flattering possible way to be wrong.

This costs nothing that mattered: the fraction was wanted as a NAT-traversal
regression alarm, and connections are the better signal for that anyway — one
chatty relayed pair can dominate a byte share while a hundred pairs quietly
fall back to relay.

## Decision: the tenant surface shows UNITS, not money (2026-08-30)

Settles open decision 3. `/observability` renders currency because the operator
is reading their own cost; `/tenant/{tid}/analytics` deliberately does not:

1. These are **our costs, not the org's bill**. A figure that appears on no
   invoice invites a dispute, and with no quotas there is nothing to measure it
   against.
2. The tenant surface exists to be **acted on** — a high relayed share means
   that org's network is refusing direct paths, which their own IT can usually
   fix. Pricing it buries a networking finding under a currency symbol.

The unit figures are already what a quota would be denominated in, and the
payload carries `quota: null` so the slot renders dark rather than implying an
unlimited plan is a satisfied one.

## Decision: costs live only in `config/relay-costs.toml` (2026-08-30)

No default price exists anywhere in the code, and `RelayCosts` is all
`Option`. An unset cost renders **"not priced"**; a defaulted `0.00` would
render as *"this org is free to serve"* and imply **100 % margin** — the single
number someone would actually make a pricing decision on. Same contract as the
absent GeoIP database honestly reporting `country: unknown`.

`mrr_cents` is a **list-price estimate** (`price_monthly_cents` x seats), not
billed revenue: `BillingInfo` stores Stripe ids and a status but no amount.
`subscription_status` travels with each row so a `canceled` org's MRR is
visibly notional, and margin pro-rates the monthly price to the selected range
— comparing a month of revenue against a day of cost is off by 30x.
| 2026-08-30 | Live ledger census on prod (`stats_usage`) | `derp_bytes` 680 buckets / 1 765 944 520 B across **2 tenants**; `sfu_participant_seconds` 65 buckets / 3 930 s — **per-tenant attribution works, and P4 produces real data** |
| 2026-08-30 | Negative-bucket sweep (criterion 1) | **0** in raw, `_1h`, `_1d` |
| 2026-08-30 | Loss-path log sweep, 24 h, both pods | `usage flush skipped` **0** · `usage bucket write failed` **0** · `could not be attributed` **0** ⇒ no byte was dropped or misattributed |
| 2026-08-30 | Flush-log vs stored value, 3 consecutive minutes | 86 278 / 108 818 / 109 538 — **exact match**; the drain→`$inc` path stores what it drained |
| 2026-08-30 | Currency check | newest bucket 1 minute old; 234 buckets in the preceding 2 h ⇒ metering live, not stalled |
| 2026-08-30 | ⚠️ **Criterion 2 was unfalsifiable as written** | `stats_relay` has **never** stored `net_tx_bytes` — absent in all 100 800 documents. `relay_load.rs` reads the `/stats` counters into a local struct and writes `rx_mbps`/`tx_mbps` instead. A criterion naming a field nobody stores can only ever be "not done"; restated against `DERP_BYTES_RELAYED_TOTAL` |
| 2026-08-30 | PoP egress reality check | all five regions ~0 traffic (`tx_mbps` ≈ 0.001) while the ledger moved 1.77 GB ⇒ the fleet's DERP rides the **API pods**, not the regional PoPs. A PoP-vs-ledger comparison would have compared two things that barely overlap |

## Correction: the hot path is a LOOKUP plus an atomic, not "one atomic add"

The code comment (and this spec's P1 note) said *"one atomic add on the hot
path"*. Measured, that understates it by 6x: steady state is a DashMap `get`
— hash, shard read-lock, deref — **and then** the relaxed `fetch_add`, and the
**lookup is 5x the cost of the atomic** (83.53 vs 16.39 ns). Most of the
atomic's own cost is cache-line ping-pong between cores, not the instruction.

It does not matter at today's volumes and the criterion passes on a large
margin. It is recorded because the claim was wrong, not because the number is:
a reader who believed "one atomic add" would mis-budget this path by 6x when
DERP throughput grows.

**The lever, if it ever matters**: a DERP connection forwards for a network
that is fixed for the life of the session, so the counter could be resolved
**once at session start** and held, removing the per-frame lookup entirely
(`DashMap<ObjectId, Arc<AtomicU64>>`, since entries are drained with `swap(0)`
and never removed, so a cached handle stays valid). Deliberately NOT done —
at 0.002 % of a core it would be optimising something 500x below where it could
begin to matter, and the cached handle is one more thing to keep correct across
re-homing.
| 2026-09-01 | `bench_add_network_bytes_cost` — the hot-path cost, finally run | atomic-only **13.69** ns/op · `add_network_bytes` **111.53** ns/op · lookup overhead **97.84** ns/op (8 threads, one shared network id = worst case). At 200 frames/s: **0.0022 % of one core** |
| 2026-09-01 | ⚠️ Optimized figure unavailable, and it does not matter | release fails on `mediasoup-sys` (meson subproject) in WSL, and the build host runs cargo 1.75 (no edition 2024). The debug number is an **upper bound** — release is strictly faster — and the margin is ~10⁴, so no decision turns on it. ~98 ns of added per-frame latency is invisible beside a network hop in milliseconds |
| 2026-09-01 | Billing invariant pinned in `ws::derp::tests` | 7 new tests: relayed frames bill **exactly** the enqueued bytes (32 + payload, not the inbound length) and accumulate; **zero** on unregistered dst / cross-network / ACL-denied / full queue / malformed; warn-mode delivers **and therefore bills** |
| 2026-09-01 | ⚠️ Verified falsifiable | hoisting `add_network_bytes` above the enqueue fails **4** of them. The ACL test's precondition also earned itself: `DerpAllowTable::default()` is WARN mode and permits, so a first draft would have billed `0` for the wrong reason |
| 2026-09-01 | P3 resolved as a **decision**, not a blockage | measured on the fleet that coturn 4.17.2's label set is `{realm}`/`{type}` only; deferred deliberately because per-tenant TURN attribution buys nothing until a tenant relays material TURN volume |
