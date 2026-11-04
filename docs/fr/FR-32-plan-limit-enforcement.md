<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# FR-32 — Eleven of fourteen plan limits are advertised and enforced nowhere

**Issue:** [#898](https://github.com/gjovanov/roomler-ai/issues/898) ·
**Status:** P0–P1c + integration tests shipped; **P2 complete for existing tenants** (all 65 on `Enforce`); default stays `Warn` by standing decision · field-verified on `v20260830-eaba9f4b0554` ·
**Parent arc:** pricing (P1 of the sequence agreed under [FR-24](FR-24-licensing-split.md))

## Goal

Make the plan matrix true. `GET /api/stripe/plans` publishes fourteen limits per tier and
takes money against them; three are enforced. A customer on Free is told they get 10
members, 5 channels and 100 MB, and the server will happily give them ten thousand of each.

This is **P1 of the pricing arc**, whose ordering was settled deliberately:

> **P1 enforce → P2 meter ([FR-20](FR-20-relay-cost-metering.md), #807) → P3 reshape tiers
> on MEASURED cost → P4 offline keys. Never invert.**

The brief this replaced priced *before* measuring, while admitting its numbers were not
researched. Nothing here re-prices anything: re-pricing is P3 and is gated on FR-20's
per-tenant cost data.

## Root-cause evidence (read on `057aa6e9`, 2026-08-29)

`Plan::limits()` (`crates/db/src/models/tenant.rs:180`) returns a 14-field `PlanLimits`.
Every field is serialised into the public plan matrix by `crates/services/src/stripe.rs`
(lines 313 / 327 / 341). Only these three read it back:

| Call site | Limit | Enforced |
|---|---|---|
| `crates/api/src/routes/agent_org.rs:210` | `max_devices` | yes |
| `crates/api/src/routes/remote_control.rs:157` | `max_devices` | yes |
| `crates/api/src/routes/tunnel.rs:132` | `max_tunnel_clients` | yes |

**Everything else is dead.** `grep -rn '\.limits()' crates/` returns exactly the three rows
above plus the three that *construct* the advertised matrix. The eleven unenforced fields:
`max_members`, `max_channels`, `max_message_history`, `storage_bytes`,
`video_max_participants`, `max_concurrent_sessions`, `exit_nodes`, `magic_dns`,
`recordings`, `ai_recognition`, `cloud_integrations`.

`overlay_mesh` is the fourteenth and is `true` on every tier — vacuously satisfied, not
enforced. It is a marketing row, not a gate, and this FR leaves it alone.

Two findings that were **not** in the prior evaluation:

1. **There is a second, competing source of truth.** `TenantSettings` carries its own
   `max_members: u32` and `file_upload_limit: u64`, shadowing `PlanLimits.max_members` and
   `PlanLimits.storage_bytes`. Both have **zero readers in the entire workspace** — `grep`
   finds `max_members` only in `crates/tests/src/billing_tests.rs:48`, asserting the
   advertised JSON, and `file_upload_limit` / `storage_bytes` nowhere at all. So this is
   not "two enforcers disagreeing": it is two dead fields shadowing two dead fields, and
   whichever one gets wired becomes the answer by default. Decide it, don't inherit it.
2. **The counting primitives mostly do not exist.** `count_active_for_tenant` exists on the
   `agent` and `tunnel_client` DAOs — precisely the two limits that are enforced. Every new
   gate needs its count built first, and *that*, not the `if`, is the work.

`Plan::Enterprise` is a phantom: `tenant.rs:226` gives it Business's limits, `:250`
Business's price (1600), and `get_plans()` never returns it. It is reachable only by writing
the enum value straight into a tenant document.

## Key design

### 1. Observe before enforcing — the house pattern, for the house reason

Switching eleven gates on against a live fleet **locks out tenants who are already over the
line**, and it was us who put them there. The precedent is already in this codebase:
`OverlayNetwork.acl_mode` is `off | warn | enforce`, and `overlay_rpf` defaults to `warn`,
for exactly this reason.

So: `TenantSettings.plan_enforcement: Off | Warn | Enforce`, **default `Warn`**.

- `Off` — no check runs.
- `Warn` — the check runs, the denial is **recorded and logged**, the request **succeeds**.
- `Enforce` — the denial is returned.

`Warn` is the default rather than `Off` because a mode that does nothing produces no data,
and the entire purpose of P1 is to learn who *would* be denied before anyone is.

> ⚠ **That rationale is now historical.** The observe phase is over and every existing tenant
> is on `Enforce`, but the default is still `Warn` — for a *different*, deliberate reason. See
> "Standing decision: the default stays `Warn` during early growth" below before changing it.

### 2. One decision point, not eleven

The three existing sites are already copy-paste: count, compare, hand-format a `Forbidden`
string. Eleven more means eleven chances to forget the log line, the mode check, or the
audit row.

One helper instead — `services::quota::check(tenant, Limit::MaxChannels, used)` returning
`Result<(), QuotaDenial>` — so mode handling, structured logging and the audit write happen
in **one** place. Same argument the SSH work settled on: *the refusals are the load-bearing
rows, so recording them cannot be per-call-site* (`decide` returns
`Result<Granted, SshDenyReason>` and `dispatch` records both arms).

`Limit` is an enum and its `match` inside the helper is exhaustive, so adding a fifteenth
field to `PlanLimits` fails to compile until someone decides whether it is a gate — the same
structural trick as `RpcCap::wire()`.

### 3. The mode must not be able to weaken what was already enforced

Found while building P0. Re-pointing the three live sites through the helper, with the
mode defaulting to `Warn`, **would have stopped enforcing the device cap fleet-wide the
moment P0 shipped** — a billing regression arriving inside a change that reads as a tidy-up,
and one no reviewer would likely catch, because the diff looks like pure extraction.

So `Limit::is_established()` marks `MaxDevices` and `MaxTunnelClients`, and an established
limit **ignores the mode entirely**. `PlanEnforcement` stages *new* enforcement; it is not a
switch that turns billing off. A unit test asserts both established limits refuse under all
three modes, so the property cannot be quietly deleted.

### 4. `u32::MAX` is the "unlimited" sentinel, not a number

`PlanLimits` spells unlimited as `u32::MAX` (`Pro.max_members`, `Pro.max_channels`,
`Business.max_concurrent_sessions`) and `-1` for `max_message_history` — not as `Option`.
The first draft of the helper compared against it as a real cap. That is wrong twice: it
would refuse a tenant the published matrix calls unlimited, and it would file denial records
with a `max` of 4 294 967 295 — **poisoning the exact dataset P2 and P3 exist to read**.

Caught by a unit test written before the bug was suspected; the test now pins the sentinel.

### 5. Denials are data

Every check in `Warn` or `Enforce` emits a structured record: tenant, limit, `used`, `max`,
plan, mode, outcome. This is what P2 and P3 read to reshape tiers — "how many Free tenants
are over 10 members, and by how much" is a **pricing input**, not a log line.

Deliberately **not** a new collection on day one: `quota_denials` rows are only worth keeping
once the gates are wired. P0 logs; P1 adds the collection if the volume justifies it.

## Phases

| # | Scope | Kill switch |
|---|---|---|
| **P0** | `plan_enforcement` mode + `services::quota` helper + `Limit` enum + structured denial logging. **No new gate wired.** Re-point the 3 existing sites through the helper, behaviour byte-for-byte identical. | mode `Off` |
| **P1** | Build the missing `count_*` DAOs and wire all 11 limits, **shipped in `Warn`**. Nothing is refused. | mode `Off` |
| **P1c** | `GET /api/admin/plan-compliance` — the snapshot that tells an operator who is already over the line, so P2 has an input on deploy day. | read-only |
| **P2** | Read the compliance report. Grandfather over-limit tenants, then flip to `Enforce` tenant by tenant. | per-tenant mode |
| **P3** | Resolve the shapes: delete or repurpose `TenantSettings.{max_members,file_upload_limit}`; give `Enterprise` real limits and a price, or remove the variant. | n/a — schema only |

Gates by enforcement point (P1):

| Limit | Point |
|---|---|
| `max_members` | `invite::accept_invite:157`, `invite::add_member:479` |
| `max_channels` | `room::create:126` |
| `storage_bytes` | `file::upload:249`, `file::upload_room:443` |
| `recordings` | `recording::create:55` |
| `exit_nodes` | `overlay_route::set_exit_node:312` |
| `magic_dns` | `overlay_route::set_magic_dns:471` |
| `ai_recognition` | `integration::recognize_file:16` |
| `cloud_integrations` | **no enforcement point — the feature has no call path** (see below) |
| `video_max_participants` | call join (`crates/services/src/media/`) |
| `max_concurrent_sessions` | remote-session start |
| `max_message_history` | message read path — **a retention bound, not a gate** (see Open decisions) |

### Found in P1a: `cloud_integrations` is sold but not implemented

`crates/services/src/cloud_storage/` (dropbox, google_drive, onedrive) is declared in
`services/src/lib.rs` and **referenced by nothing else in the workspace** — no route, no
`AppState` wiring, no UI. The `StorageProvider::{GoogleDrive,OneDrive,Dropbox}` enum variants
and the `TenantSettings` OAuth credential fields exist, but no code path ever constructs a
client.

So this is not an unenforced limit — it is an **advertised feature with no implementation to
gate**. Deliberately left unwired rather than given a gate at an invented call site: a check
in front of nothing would read like coverage and assert nothing. The gate goes in when the
feature does, in the same change.

### Found in P1a: only *enabling* may be gated

`exit_nodes` and `magic_dns` are toggles, and the gate is on the **enable** path only.
Gating the disable path too would mean a plan downgrade could leave a tenant holding an exit
node or a DNS zone they are not allowed to turn off — strictly worse than the feature having
been free. Same rule for any future toggle.

### Found in P1b: `max_concurrent_sessions` has no table to count

`RemoteSessionDao::create` has **zero callers workspace-wide**. Nothing ever writes a
`remote_sessions` row — live sessions exist only in the Hub's in-memory `DashMap`, and the
per-agent `active_sessions` / `max_sessions` pair there is a *different*, unrelated cap.

A Mongo-backed gate would therefore count an empty collection forever: it could never fire,
while reading in review exactly like a working control. Withheld for the same reason as
`cloud_integrations`. Wiring it means either persisting sessions or counting the Hub (pod-local,
which is *correct* under tenant-affinity routing but is a real coupling to state, not a query).

⚠ Related and worth its own look: `routes/usage.rs` reports remote-desktop usage by reading
that same never-written collection.

### Found in P1b: a byte quota cannot be a `used >= max` test

The other counted limits add one thing at a time. `storage_bytes` does not — a tenant at
99 MB of 100 MB must be refused a 10 MB upload and **allowed** a 100 KB one. A bare
"are you at the cap" test accepts both, right up until the quota is already blown, and then
rejects a 1-byte file.

Hence `check_delta(current, delta)`, with `check` defined as `delta = 1` so the two forms
cannot drift. Refuses on `current + delta > max`, so a file that exactly fills the quota still
fits, and the add saturates so a pathological delta cannot wrap into "fits".

### Decisions taken (operator, 2026-08-29)

1. **`PlanLimits` is the single source of truth.** `TenantSettings::{max_members,
   file_upload_limit}` are **deleted** — zero readers, no API exposure, no UI, and serde
   ignores the leftover key in existing documents. The earlier "plan-as-ceiling +
   settings-as-lower-override" idea was dropped: it was justified as giving P2 grandfathering
   for free, and it does not — grandfathering needs a *higher* override, and the
   `plan_enforcement` mode already provides it. A per-tenant override belongs with a real
   `Enterprise` tier, added deliberately.
2. **`max_message_history` is not gated.** Only bound-reads is defensible (delete destroys
   data; refuse-writes makes a chat product read-only), but doing it honestly means
   `find_in_room` + `find_pinned` + `find_thread_replies` + both exports + search — miss the
   exports and it is theatre. It also has almost no cost basis; it exists for upgrade
   pressure. P1's question is answered instead by `MessageDao::count_for_tenant`, a
   **reporting query with no gate**, so P3 can decide whether the limit survives at all.

### P1c: the observe phase wants a snapshot, not an event log

Open decision 4 asked whether denials get their own collection. Answering it revealed the
question was wrong.

P2 has to know **who is already over a limit** so they can be grandfathered before anyone is
flipped to `Enforce`. A denial log cannot answer that: it only ever sees tenants who happen to
call the API during the observe window. A tenant sitting at 40 members on a 10-member plan
that nobody adds to this month emits **nothing** — and would be flipped straight into a wall.
It also means waiting weeks for data to accumulate.

A snapshot has neither problem: it is complete, it includes idle tenants, and it answers on
the day the code deploys. So `GET /api/admin/plan-compliance` (platform-admin, 404 on miss)
reports every tenant's current usage against its plan, worst first, with a `would_break` flag.

The `tracing::warn!` line stays: it records *frequency* — how often people actually collide
with a limit — which is a genuine P3 pricing input and a different question from "who is over
now". A `quota_denials` collection is therefore **not** needed for P2, and P3 can decide
whether frequency is worth persisting.

⚠ The report reads its limits through `quota::Limit::describe`, the same function the gates
use. A report that recomputed them independently could call a tenant compliant while the gate
refuses them — worse than having no report. A unit test pins this.

⚠ `over` in the report is **strictly greater** than the cap, while the *gate* refuses the next
one *at* the cap. They answer different questions ("are you outside your plan" vs "may you add
one more"), and conflating them would mark every tenant exactly at its limit as breaking.

## Acceptance criteria

- [ ] `grep -rn '\.limits()' crates/` shows **no** hand-rolled comparison outside `services::quota`.
- [ ] Adding a field to `PlanLimits` fails to compile until it is classified in `Limit`.
- [ ] A Free tenant at 10 members: `add_member` **succeeds** under `Warn` and emits one denial record naming `max_members`, `used=10`, `max=10`; **refuses 403** under `Enforce`; is unaffected under `Off`.
- [ ] The same assertion once per wired limit — 11 tests, each proving the gate fires *and* that `Warn` does not refuse.
- [ ] P0 changes no observable behaviour: the 3 existing device/tunnel refusals return the same status and the same message before and after the helper lands.
- [ ] Denial records are queryable per tenant, so "who would break" can be answered before any flip.
- [ ] No tenant is moved to `Enforce` without its warn data being read first — recorded per tenant in the field log.

## Standing decision: the default stays `Warn` during early growth

**Operator, 2026-08-30.** Every existing tenant is on `Enforce`, but
`PlanEnforcement::default()` remains `Warn`, so **new signups are not enforced**.

The original justification for that default is spent — it existed for the observe phase, which
is over. The current justification is different and deliberate:

- The grandfathering hazard **does not apply to a new tenant**. It starts at zero usage and
  cannot be retroactively over a limit, so `Warn` is not protecting anyone from a state we put
  them in.
- It is a **go-to-market choice**: while the product is in early growth, a promising signup must
  not be stopped at 10 members or 100 MB before anyone has spoken to them.

⚠ The consequence, stated plainly because it reads like a bug: the advertised plan limits **do
not fire for anyone who signs up**. That is intended, for now, and is recorded on the
`PlanEnforcement` enum itself so the next reader does not "fix" it.

**Revisit when** the product leaves early growth, or when a real (non-test, non-internal) tenant
is on a paid plan — whichever comes first. Flipping `#[default]` to `Enforce` is the whole
change.

## Open decisions

1. **`max_message_history` is not a gate.** Free advertises 5 000 messages; enforcement could
   truncate reads, refuse writes, or delete. Truncating reads silently hides a customer's own
   data; deleting destroys it. Leaning: bound the *read* window and say so in the API
   response, never delete — but this needs the operator's call, and it is the one limit that
   can lose data.
2. **Which `max_members` wins** — `PlanLimits` (plan-derived) or `TenantSettings`
   (per-tenant)? Leaning `PlanLimits` as the ceiling with `TenantSettings` as an optional
   *lower* override, which also hands P2 its grandfathering mechanism for free.
3. **`Enterprise`** — give it real limits and a price, or delete the variant? It currently
   charges Business money for Business limits under a different name.
4. Do denials get their own collection with a TTL (like `exec_audit`), or is structured
   logging enough until P2 needs to query them?
5. **`TenantSettings.max_members` defaults to 100 while Free's `PlanLimits.max_members` is
   10** — the two dead sources of truth disagree by 10×, so whichever is wired changes who
   is over the line. Found during P0; feeds decision 2.

## Out of scope

- **Any change to prices or tier shape** — that is P3, gated on FR-20's measured cost.
- Metering relay bytes (FR-20, #807).
- Offline licence keys (P4 of the arc).
- `overlay_mesh`, which is `true` on every tier.
- Anything agent-side; these are all server-side control-plane gates.

## Field-verification log

### 2026-08-29 — P0 + P1a + P1b + P1c live on prod `v20260829-0da90b766dc0` (#904 → `e95907ff`)

**Falsifiable check, with a control.** The report route was measured **before** the roll and
after, plus a never-existing path to prove the discriminator:

| Path | Before | After |
|---|---|---|
| `/api/admin/plan-compliance` | **404** (absent) | **401** (present, auth required) |
| `/api/admin/stats/orgs` (control, unchanged) | 401 | 401 |
| `/api/nonexistent-control` | 404 | 404 |
| `/health` | 200 | 200 |

A 404→401 transition while a known-missing path still 404s is the route shipping, not a
coincidence of gateway behaviour.

**The report returns real data** (fetched as a platform admin in the operator's own browser):
65 tenants, and fleet-wide non-zero usage across every aggregation — `MaxMembers` 111,
`MaxChannels` 67, `MaxDevices` 27, `MaxTunnelClients` 11, `StorageBytes` 26 112 358,
`MagicDns` 2, `MaxMessageHistory` 97. ⚠ This check is the load-bearing one: an all-zero report
is indistinguishable from "everyone is compliant", so the totals had to be shown non-zero
before `would_break: 0` could mean anything.

**Result: `would_break = 0` of 65 tenants.** Nobody is over a gated limit, and nobody is even
*at* one — the closest is `Conf Org [Free] MaxChannels 1/5`, at 20 %. So **P2's grandfathering
step is a no-op**: tenants can be flipped to `Enforce` without any of them being refused.

**Every tenant deserialised to `Warn`** (65/65), confirming the `#[serde(default)]` on
`plan_enforcement` lands pre-FR-32 documents in observe mode as designed.

**No regression:** zero panics, zero `5xx`, zero `compliance query failed`, and zero
`plan limit exceeded` lines in 12 minutes across both pods.

#### Two pricing findings the report surfaced

1. **`Enterprise` is not just a phantom tier, it is the ONLY paid tier in use.** Plan
   distribution is **63 Free · 2 Enterprise · 0 Pro · 0 Business**, and both Enterprise
   tenants are internal (`Grox`, `Jovanov`). The two tiers Stripe actually sells have **zero
   adoption**, while the only non-Free tenants sit on a tier `get_plans()` never returns.
   That reframes open decision 3: it is a P3 pricing input, not a tidy-up.
2. **The gates are inert against real data, by measurement rather than by assertion.** Free's
   caps (10 members, 5 channels, 100 MB) are far above what any Free tenant on this
   deployment actually uses, which is itself worth knowing before P3 re-prices them.

---

**Renumbered from FR-31.** [#897](https://github.com/gjovanov/roomler-ai/issues/897)
(opening-keyframe budget) claimed `FR-31` with the lower issue id, and the repair rule is
that the lower issue number keeps `FR-N` while the higher renumbers. `FR-32` was checked to
be *free* rather than *vacated* before being taken — `git log -S "FR-32"` over the ledger
returns nothing and no issue was ever titled FR-32 — because a vacated number must never be
reused.

### 2026-08-30 — P2 complete for existing tenants; AI recognition removed

**All 65 live tenants moved to `Enforce`** (`matched=65 modified=63` — the two Enterprise orgs
were already there; `not-enforce remaining: 0`). Checked first that no live lane depended on the
test-debris tenants: the newest is **183 days old** and **0 tenants** were created in the
preceding 7 days. App-level confirmation: `/health` 200, `/api/stripe/plans` 200, and **0**
deserialisation errors / ERROR / panics across 3 258 log lines.

**AI document recognition removed entirely** (#974, `8d8d07a04`, deployed
`v20260830-eaba9f4b0554`) after verifying it unused in prod — `recognized_content` on 0 of 22
files, 0 recognition tasks ever. −643/+52 across 25 files, including the `MESHHARBOR__CLAUDE__*`
config surface. `POST …/recognize` now returns **404**.

**Free video 0 → 4** (#959, deployed `v20260830-078ebef47b2a`), advertised publicly.

The report's verdict across the arc — the same number meaning three different things:

| State | `would_break` | Why |
|---|---|---|
| before the coverage fix | 0 / 65 | the video gate was not measured |
| after the coverage fix | 63 / 65 | every Free tenant would have lost conferencing |
| after Free → 4 | 63 / 65 | `AiRecognition` only |
| after removing AI recognition | **0 / 65** | genuinely clean, and now trustworthy |
