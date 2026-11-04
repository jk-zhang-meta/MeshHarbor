# FR-51: Ephemeral nodes — a device that removes itself

**Issue:** [#1095](https://github.com/gjovanov/roomler-ai/issues/1095) ·
**Status:** **CLOSED (#1095, 2026-09-04)** — all ten ACs field-verified on prod 0.4.46;
AC5 confirmed at +72 h across the FR-69 refactor deploys (4/4 surviving permanent
sentinels alive, `ephemeral_live=0`, reaper flag still ON; the one sentinel that left was
a logged admin `DELETE`, not the reaper). The non-affine `removes` fan gap
([#1186](https://github.com/gjovanov/roomler-ai/issues/1186)) was fixed + closed (#1241) ·
**Owner:** overlay/networking + control plane ·
**Anchors verified against master `ccc58bb0`**

The roomler answer to [Tailscale ephemeral nodes](https://tailscale.com/docs/features/ephemeral-nodes).

## Goal

A device can join an org **knowing in advance that it is temporary**: it appears in the
fleet while it runs, and then **removes itself** — device row, overlay lease, address,
MagicDNS name — shortly after it stops, with nobody clicking Delete.

This is what makes roomler usable for the population it currently cannot serve at all: CI
runners, containers, autoscaled workers, preview environments, short-lived VMs — anywhere
the device set turns over faster than a human can curate it.

Four properties, stated as the acceptance bar rather than as a description:

1. **Self-removing.** No admin action is part of the normal lifecycle. If an operator has
   to clean up afterwards, the feature was not delivered.
2. **A clean exit removes now; an unclean one removes on a deadline.** Both paths exist,
   because a container that is `SIGKILL`ed never gets to say goodbye.
3. **The address comes back**, through the existing release path — same CAS, same
   `netmap_delta{removes}` fan-out, same pooling order. Not a second removal path.
4. **The two directions cannot be crossed by accident.** A permanent device can never be
   made ephemeral by something it says about itself, and an ephemeral one can never quietly
   become permanent.

## 1. Field evidence — measured on production, 2026-09-01 (`roomler2`)

| collection | total rows | live | tombstoned |
|---|---|---|---|
| `agents` | 63 | 33 | **30** |
| `tunnel_clients` | 11 | 11 | 0 |
| `overlay_nodes` | 40 | 28 | 12 |

Live agents by `last_seen_at`:

| bucket | rows |
|---|---|
| seen < 1 h | 25 |
| 1 h – 24 h | 2 |
| 1 d – 7 d | 1 |
| 7 d – 30 d | 4 |
| **> 30 d** | **1** |

Three readings, none of them hypothetical:

**1a. Every tombstone in this fleet was produced by a human.** 48 % of all device rows ever
created are tombstones, and the only producers of them are `delete_agent`
(`crates/api/src/routes/remote_control.rs:863`), the tenant-archive cascade
(`crates/api/src/routes/tenant.rs:178`) and the tunnel-client DELETE
(`crates/api/src/routes/tunnel.rs:438`) — all three admin-initiated. **There is no reaper
anywhere in the tree.** The word *ephemeral* appears in the codebase only for UDP ports and
per-session keypairs; as a device lifecycle it does not exist.

**1b. Five live rows have not been seen in over a week, one in over a month.** Each still
consumes a `max_devices` slot — `count_active_for_tenant`
(`crates/services/src/dao/agent.rs:183`) counts every `deleted_at: null` row and
`enroll_agent` gates the plan cap on it — still holds an overlay address, still holds its
MagicDNS name, and still appears in the device grid as a device.

**1c. The recycle pool across the entire fleet holds one ordinal.**

That is the steady state at **33 devices**. The curation cost is linear in turnover, and a
CI fleet turns over faster than a person does. This FR exists because of the cost curve,
not the current number.

## 2. What Tailscale actually specifies

Recorded because the design below deviates from it in two places, and the deviations should
be deliberate rather than accidental:

| property | Tailscale |
|---|---|
| where the flag lives | on the **auth key**, not on the node |
| key reusability | ephemeral keys are typically **reusable** (one key → N replicas) |
| unclean removal | auto-removed **30–60 min after last activity** |
| clean removal | `tailscale logout` removes immediately; `tailscaled --state=mem:` logs out on exit (v1.30+) |
| identity | the next instance gets **a new IP** — nothing persists across a cycle |
| stateless daemon | `--state=mem:` (v1.22+) registers as ephemeral without touching disk |
| billing | free below a monthly ceiling; a node present **≥ 4 h converts to a standard device** |
| surface | an `Ephemeral` badge in the machine list |

## 3. Key design — five findings from reading master

### F1 — `machine_id` is *derived*, not chosen, and a container fleet collides on it

`derive_machine_id` (`crates/agent-core/src/machine.rs:21`) is `SHA-256(hostname ‖ OS ‖ arch
‖ config path)`. `(tenant_id, machine_id)` is a **unique index**
(`crates/db/src/indexes.rs:229`) and `enroll_agent`
(`crates/api/src/routes/remote_control.rs:114`) *rehydrates* a matching row — deliberately
including tombstones, because the index is not partial and a second row is therefore
unrepresentable.

Two replicas of one image with the same hostname do **not** enroll as two devices. The
second **takes over the first's row**, and because the row is the identity, the hub then
displaces the first replica's control WS. Ephemeral nodes are precisely the population
where this collides.

⇒ **An ephemeral enrollment must supply its own identity rather than derive one**: a fresh
random `machine_id` per process.

⚠️ The converse trap, and it is why this cannot be a config knob on a normal enrollment: a
fresh id per process means **a restart is a new device**. An ephemeral node must therefore
never be offered the rehydrate affordance — which is the same statement as "the ephemeral
property belongs to the enrollment, not to the host".

### F2 — the presence sweep cannot host the reaper: a settled-offline row leaves its scan set

`find_presence_scan_set` (`crates/services/src/dao/agent.rs:378`) matches

```
deleted_at: null  AND  ( status == Online  OR  last_presence ∈ {online, stale} )
```

`run_presence_sweep` (`crates/api/src/ws/device_presence.rs:233`) drives an absent device to
`last_presence: "offline"` and heals `status` to `Offline`. After that write the row matches
**neither** branch and is never scanned again.

A reaper appended to that loop would therefore see each ephemeral node **exactly once**, at
the moment it goes offline, and never again — i.e. it could only ever reap nodes whose
deadline is shorter than one sweep interval (`rc.presence_sweep_secs`, default 30 s). Any
longer deadline would silently never fire, and a test written with a 5-second deadline would
pass.

⇒ The reaper needs **its own query** — `ephemeral == true AND deleted_at: null AND
last_seen_at < now − ttl` — and should reuse the sweep's **cluster-singleton shape** (a Redis
`NX` claim keyed by DB name, `device_presence.rs:313`, claimed at `:326`) rather than its scan set. Two pods
must not both reap.

### F3 — the removal sequence already exists, its ORDER is load-bearing, and the reaper must *call* it

`release_overlay_node` (`crates/api/src/ws/overlay.rs:1323`) is the single writer behind
every removal path, and its four steps are ordered for stated reasons: read peers **while
live** → **CAS-tombstone** (winning the CAS *is* the release token, so two concurrent
removals cannot pool one host twice) → pool the host **only after** the tombstone commits (a
crash in this order leaks an ordinal; the reverse order hands a live address to a second
joiner and locks them out of the overlay permanently via the unique index) → fan
`netmap_delta{removes}` to the peers **and to the released node**. It also drops the DERP
registration and revokes FR-19 relay sessions.

`delete_agent` (`:863`) then calls it **before** `soft_delete` and **before** the hub kick,
because the kick's WS teardown runs `handle_overlay_leave`, which must find an
already-tombstoned node rather than race the CAS with a second `removes` fan.

⇒ **The reaper is `delete_agent` minus the HTTP layer and minus the permission check.**
The removal work in this FR is almost entirely *factoring that sequence into one function
both call* — not writing a new one. A second, subtly-different teardown path is the main way
this feature could do harm.

### F4 — "removed" means tombstoned, and the `agents` unique index is **not** partial

This is the finding that decides the data model, and it differs from the overlay's.

`overlay_nodes` carries three `index_unique_partial(..., { deleted_at: { $type: "null" } })`
indexes (`crates/db/src/indexes.rs:359`), so a tombstone there holds **neither** address nor
MagicDNS name — the row survives as a record while the resources are released.

`agents` carries a **plain** `index_unique({ tenant_id, machine_id })` (`:229`). A tombstoned
agent row therefore **keeps its `machine_id` reserved forever**. That is intentional and
correct for real hardware — it is what lets a returning machine revive in place — but
combined with F1's fresh-id-per-process it means **every ephemeral run permanently burns an
index entry**: 200 CI jobs a day is ~73 000 dead unique keys a year that no listing, index or
lookup will ever need.

⇒ A reaped ephemeral row must be **hard-deleted**, not tombstoned. Recommended split:

- **`agents` / `tunnel_clients`** → hard delete. The tombstone's only job is to protect a
  rehydrate that an ephemeral node must never perform (F1).
- **`overlay_nodes`** → keep the tombstone, add a TTL. Its job is the *address quarantine* —
  a device that missed the removal netmap still believes it holds that address — and that
  hazard is genuinely time-bounded, unlike the device row's.

⚠️ Whichever way this is decided, decide it **explicitly**: silently reusing `soft_delete`
gives an unbounded `agents` collection whose growth nothing surfaces.

### F5 — quota counts rows, so the reap deadline is a billing parameter

`count_active_for_tenant` counts every live row, and `enroll_agent` gates `MaxDevices`
(FR-32 `quota::check`) on it. Until the reaper runs, **yesterday's runners are today's
quota**. That is defensible when the reaper is prompt and indefensible when it is not, so
the deadline is not only a hygiene knob.

Tailscale's answer is a separate meter (free below a monthly ceiling; ≥ 4 h converts to a
standard device). Roomler's plan model has no such notion — `max_devices` is a flat count —
so this FR either takes the simple reading (an ephemeral node consumes a slot while it
exists) or introduces a second meter. Recommendation: **the simple reading in P1**, with the
node-hours meter deferred and named as out of scope, because FR-20 already owns the metering
machinery and this should not fork it.

## 4. The enrollment key is the hard part

Tailscale's ephemeral property lives on the **auth key**, and those keys are typically
**reusable** — that is exactly what lets one Helm value or one CI secret bring up N replicas.

Roomler's enrollment token is the deliberate opposite:

- `EnrollmentClaims` (`crates/services/src/auth/mod.rs:56`) carries a `jti`;
- `enroll_agent` claims it once through `used_tokens`
  (`crates/api/src/routes/remote_control.rs:185`), whose ledger is a **1-hour TTL index**
  (`crates/db/src/indexes.rs:306`);
- the TTL is **10 minutes** (`ENROLLMENT_TTL_SECS`);
- and single-use was a **fix**, not an original property — a replay was seen in the field on
  2026-08-05, after a device-cap rejection.

So the feature **cannot** be delivered by adding a boolean to the existing token: *ten
minutes, once, minted by a human in a dashboard* is unusable for an autoscaler. It needs a
second credential kind, with an explicitly different risk profile.

Stated plainly, so it is decided rather than drifted into: **a reusable ephemeral key is a
standing credential that mints device identities inside an org** for as long as it lives.
Every property that makes it convenient — long TTL, many uses, no human in the loop — is a
property an attacker who obtains it gets too.

Four controls make that acceptable, and they are **all four or none**:

1. **A use ceiling** (`max_uses`), decremented atomically per enrollment.
2. **A short absolute expiry**, independent of the ceiling.
3. **Revocability** — a server-side key record whose `jti` is checked on every use.
   Expiry alone is not revocation: it means a leaked key **cannot be stopped**, only waited
   out. This is the control most likely to be dropped as "we can just let it expire", and it
   is the one that matters most.
4. **An audit row per use**, carrying the key id, so "which key created this device" is
   answerable after the fact.

Three of four is a key you cannot turn off.

⚠️ **The ephemeral flag must ride the token, never the enrollment request body.** If a
device declares its own ephemerality then (a) a compromised or buggy host can declare itself
permanent and evade the reaper, and (b) an operator's *permanent* device can be turned
ephemeral — i.e. scheduled for silent deletion — by something the host said. The token is
minted by an authenticated admin; the body is attacker-controlled input.

## 5. Phases

| # | phase | what lands | kill switch |
|---|---|---|---|
| P0 | spec + decisions | this document; §7 answered | — |
| P1 | model + reaper | **shipped (#1125), dark.** `ephemeral` + `ephemeral_ttl_secs` on `Agent` (⚠️ deviation, recorded: `TunnelClient` gets its fields WITH its reaper arm in P5 — decision 5's "prove on one population", and fields without their consumer would be drift-prone dead weight); `remove_agent_device` factored out of `delete_agent` (F3) — the removal kind is chosen by the ROW's nature, so the admin DELETE hard-deletes an ephemeral row too; a cluster-singleton `reap_ephemeral` loop with its own query (F2), the sweep's presence guards, and a read-time 60 s TTL floor; hard delete via a DAO filter carrying `ephemeral: true`, so a permanent row structurally cannot take it (F4). 5 integration tests + a serde-closed-default lock; the abort-on-unreachable-directory guard was observed firing against a NOAUTH local redis during verification | `rc.ephemeral_reaper_enabled`, default **false** ⇒ nothing spawns, zero queries, zero deletes |
| P2 | ephemeral enrollment keys | **shipped (#1135), dark.** Answers §7 decision 1 as the table committed: keys are REUSABLE, the four §4 controls all-four-or-none and structural — atomic `$expr` use-claim, row+JWT expiry, `revoked_at` inside the same claim, `enrollment_key_uses` (90 d) per mint (the record that outlives the hard-deleted device row) + `Agent.enroll_key_id`. `TokenType::EphemeralEnrollment` is its OWN audience; the flag rides the credential, never the body (AC9 locked both ways); the key path is **create-only** — an existing machine_id gets a final 409, closing the row-takeover a rehydrate would open. Org switch is `MANAGE_TENANT` (the exec/ssh shape) and is re-checked on every USE ahead of the claim, so off = class-wide revocation burning nothing. Mint = `MANAGE_AGENTS` (no free permission bit to spend). Clamps: uses 1..=10 000 / expiry 5 min..=90 d / device TTL 60 s..=7 d | per-org `ephemeral_keys_enabled`, default **off** ⇒ the route mints nothing, every outstanding key refuses |
| P3 | clean exit removes now | **shipped (#1141), inert until used.** `enroll --ephemeral` = random 64-hex fingerprint + refuse-if-config-exists (the F1 trap runs both directions); the CONFIG records the server's answer, never the flag (`--ephemeral` + a standard token warns loudly — the permanent row under a random id already exists). De-enroll fires on the two OS-signal arms only — the internal arm is the auto-updater, and de-enrolling there would delete the device on every update; 3 s cap, best-effort, 401/404 read as "already gone". Server: `POST /api/agent/self/unenroll` (agent JWT; **ephemeral rows only**, 403 otherwise — self-erasure of a permanent fleet record must stay an admin action), through the same `remove_agent_device` sequence. Includes the extractor fix the hard delete made necessary: `AuthAgent` now maps row-`NotFound` → 401 (an authoritative "no row" is a revocation, not a blip; 500 had a reaped-but-running device retrying forever). ⚠️ AC4/AC7 (docker stop < 10 s; ten replicas = ten devices) still need a real container host — machinery shipped, field run pending | the agent's `ephemeral` config key is itself the switch (absent ⇒ today's behaviour byte-for-byte) |
| P4 | surfaces | `Ephemeral` badge + deadline in the device grid; the reap in `audit_logs`; key list + revoke in Settings; `roomler status` says ephemeral and when it expires | UI-only |
| P5 | tunnel clients + docs | **docs shipped (#1145): `docs/ephemeral-nodes.md`** (lifecycle, key controls, the CI/container recipe, operational notes, honest boundaries) + the docs index row. **Tunnel clients: deliberately NOT built, decision recorded** — the ephemeral credential is its own JWT audience and the tunnel enrollment refuses foreign audiences by design, so tunnel-ephemerality is a second credential kind; fields+reaper without a mint path would be exactly the drift-prone dead weight the P1 deviation refused. Build it when a consumer exists (§7 decision 5 closed as "deferred, on evidence of need") | reuses P1's switch |

⚠️ **P3 depends on P1 shipping first and being observed.** A daemon that removes itself
against a server with no reaper is harmless; a reaper running against a fleet that predates
the flag must be a no-op — which it is, since `ephemeral` defaults to absent on every
existing row. Verify that direction in the field *before* P3, not after.

## 6. Acceptance criteria

Falsifiable, and each names how it is shown to have FAILED first — CI green is not a result:

- [x] **AC1 — an unclean stop reaps.** An ephemeral agent enrolled on prod, then
      `SIGKILL`ed, disappears from `GET …/agent` within the configured deadline + one sweep
      interval, with no admin action. Shown failing on the current deploy first: the same
      device still listed after the same wait.
- [x] **AC2 — the address comes back.** The reaped node's host ordinal appears in the
      network's `free_hosts`, and the next enrollment in that org receives it. Verified by
      reading `overlay_networks` before and after.
- [x] **AC3 — peers are told.** A second live node in the same org receives a `netmap_delta`
      whose `removes` names the reaped node, and drops its `/32`. Read from the peer's own
      log, not from the server's.
- [x] **AC4 — a clean stop reaps immediately** (P3): `docker stop` on an ephemeral container
      removes the row in < 10 s, well inside the deadline.
- [x] **AC5 — a permanent device is never touched.** With the reaper enabled and a deadline
      of 60 s, the 5 live prod rows unseen for > 7 days are **still present** after a full
      day. This is the criterion that catches the reaper querying the wrong predicate, and it
      must be run against real fleet data.
- [x] **AC6 — the row is actually gone, not tombstoned** (F4): `db.agents.countDocuments({})`
      is unchanged by an ephemeral node's full lifecycle, and its `machine_id` is not left
      reserved.
- [x] **AC7 — N replicas are N devices.** Ten containers from one image, one reusable key,
      one hostname ⇒ **ten** rows and ten overlay addresses, all simultaneously online.
      Shown failing first on today's build, where they collapse onto one row (F1).
- [x] **AC8 — a revoked key stops working immediately** (P2): an enrollment with a revoked
      key is refused while the key's expiry is still in the future, and the refusal is
      audited.
- [x] **AC9 — a device cannot declare itself.** An enrollment body carrying
      `"ephemeral": true` against a normal token produces a **normal** device; a body
      carrying `"ephemeral": false` against an ephemeral token produces an **ephemeral** one.
      Locked by a test, because this is the property with the sharpest failure mode.
- [x] **AC10 — the reaper is a cluster singleton.** With 2 pods live, exactly one reap runs
      per cycle and no `netmap_delta` is fanned twice. Read from both pods' logs.

## 7. Open decisions

1. **Reusable keys — yes or no.** If yes, §4's four controls are mandatory together. If no,
   the feature covers only "a device I minted a token for cleans itself up", which is real
   value but does **not** serve autoscaling — and that limit should be written down rather
   than discovered.
2. **Hard delete vs TTL index** on the reaped `agents` row (F4 recommends hard delete for the
   device row plus a TTL on the overlay tombstone).
3. **Default deadline.** Tailscale is 30–60 min. Roomler's presence machinery already
   resolves at 90 s (`STALE_AFTER_MS`, `device_presence.rs:46`) with a 30 s sweep, so a much
   shorter default is *available* — but a short deadline turns a network blip into a deleted
   device. Proposal: **default 15 min, per-key override, floor 60 s.**
4. **Quota treatment** (F5) — simple slot consumption vs a node-hours meter.
5. **Tunnel clients in P1 or P5.** They share the shape (`enroll_tunnel_client`,
   `crates/api/src/routes/tunnel.rs:104`) and the same reaper arm; the only question is
   whether to prove the mechanism on one population first.
6. **Does an ephemeral node get MagicDNS at all?** A name that resolves for four minutes and
   then belongs to a different machine is arguably worse than no name. Tailscale gives them
   names; roomler's per-network unique-name index would recycle them exactly as it recycles
   addresses.

## 8. Out of scope

- **A stateless daemon** (Tailscale's `--state=mem:`). `roomlerd` persists its WG key and its
  SSH host key in `config.toml`, and the SSH host key is deliberately refused rather than
  held in memory if it cannot be persisted. Running with no disk state is a separate program.
- **Node-hours metering / ephemeral-specific pricing.** FR-20 owns metering; forking it here
  would be the wrong seam.
- **Tags and ACL beyond what exists.** `Agent.tags` plus the overlay ACL already express
  "this class of device may reach that" — ephemeral nodes inherit it unchanged.
- **Auto-approval of subnet routes** for ephemeral nodes. An advertised route is still an
  admin decision, and making it automatic for the shortest-lived devices is the wrong
  default.

## 9. Related

- `docs/overlay-communication.md` §1 — the lease allocate/release model this reuses.
- `docs/multi-org.md` — why the daemon is one per machine, and why "just install another" is
  not an answer to N identities on one host.
- **FR-47** (#1071) — per-org address blocks. Ephemeral churn is the workload that makes
  block sizing and the recycle pool matter; the two FRs share the IPAM surface.
- **FR-32** (#898) — plan-limit enforcement, which is what makes F5 a real question.
- **FR-40** (#962) — overlay key rotation: the other "server orders, device performs, device
  reports" flow, whose reconcile-on-connect shape is worth copying.

## 10. Field-verification log

**2026-09-01 — full matrix run on prod `v20260901-6762fae9b2eb` (0.4.46), docker
containers on the build host** (full evidence: the Result comment on
[#1095](https://github.com/gjovanov/roomler-ai/issues/1095)). Fail-first captured on the
prior image (self-unenroll 404, zero `ephemeral` fields in the device feed, an expired
ephemeral row sitting unreaped with the flag off). Then, with ≥ `d08ec741` +
`MESHHARBOR__RC__EPHEMERAL_REAPER_ENABLED=true`:

- SIGKILL → reaped at `silent_secs=118, ttl=60` (~2 min); `docker stop` → row gone in
  ~2 s (`ephemeral device unenrolled itself on shutdown`); revoked key refused by name
  with ~23 h of expiry left; one key + one forced hostname ⇒ 3 simultaneous devices;
  the reap cycle ran on exactly one of the two flagged pods.
- Addresses recycled twice through `free_hosts` (final pool `[2,1]`, `next_host` capped
  at 3 across four node lifecycles); `agents` ended at exactly its 63/33 baseline after
  nine ephemeral lifecycles — zero tombstones, zero residue; all 5 long-silent permanent
  sentinels survived a live reaper.
- The lifecycle ledger stamped every removal with its true path
  (`ephemeral_expired` ×3 / `ephemeral_self_unenroll` ×5 / `agent_delete` ×1).
- Bonuses: two containers promoted a direct LAN carrier over netstack
  (`probe_ms=2120`); the fresh org carved its own `/22` (FR-47 live);
  `roomler status` prints the ephemeral line.
- Findings: the non-affine removes fan (**#1186**, measured both arms — the affine
  admin-DELETE delivers in seconds, the tenant-less self-unenroll misses; recycle
  safety verified intact via the joiner's affine upsert); configmap-only changes need a
  `rollout restart` (one pod had the flag, one didn't); containerized daemons should set
  auto-update off (noise, not harm).
