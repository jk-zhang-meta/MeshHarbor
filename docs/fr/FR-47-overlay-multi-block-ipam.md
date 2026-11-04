# FR-47: One address space per org — carve by default, grow without renumbering

**Issue:** [#1071](https://github.com/jk-zhang-meta/MeshHarbor/issues/1071) ·
**Status:** shipped — P0–P6 complete; the isolation half **field-verified in production**, the growth half (P5a–e) shipped **dark** behind `overlay.multi_block_enabled` · **Owner:** overlay/networking

## Goal

Every organization gets an overlay address range that is **its own**, from the moment the
org exists, and can **grow past its first block without renumbering a single device**.

Two properties, stated as the acceptance bar rather than as slogans:

- **Isolation is the default, not an opt-in.** Creating an org is enough to get a disjoint
  range. Nothing an operator forgets to switch on can put two orgs on the same addresses.
- **Running out is visible and survivable.** A device that cannot be given an address is
  told so; an org that fills its block is given another one instead of a refusal.

## 1. Field evidence — measured on production, 2026-08-31

`overlay_networks` + `overlay_blocks`, 66 tenants:

| network | cursor (`next_host`) | live nodes | tombstoned | free pool |
|---|---|---|---|---|
| `100.65.4.0/22` (carved) | 36 | 17 | 12 | 1 |
| `100.65.0.0/22` (carved) | 7 | 6 | 0 | 0 |
| `100.64.0.0/10` (legacy) | 3 | 2 | 0 | 0 |
| `100.64.0.0/10` (legacy) | 6 | 5 | 0 | 0 |

### 1a. Carving is OFF in production, so isolation is opt-in and nobody opts in

There is no `MESHHARBOR__OVERLAY__*` key in the prod configmap
(`k8s/base/configmap-meshharbor2-config.yaml` in the deploy repo), so the shipped default
`blocks_enabled: false` applies (`crates/config/src/settings.rs:144`, `:822`). Every
organization created today lands on the shared `100.64.0.0/10` with its cursor seeded at 1.

The two legacy rows above are therefore **not merely un-migrated — they overlap right now**.
Both orgs own `100.64.0.1` and `100.64.0.2`; one of them also owns `.3` through `.5`. The
two carved networks exist only because someone renumbered them by hand.

This is the collision class `overlay_blocks` was built to make unrepresentable, still live,
because the mechanism that prevents it was left switched off.

### 1b. Address exhaustion is invisible

`OverlayNetworkDao::allocate_host` refuses correctly and loudly at the DAO boundary. The
join path then discards that (`crates/api/src/ws/overlay.rs:357-366`): on `Err` it logs
`overlay.join: IPAM allocate failed` at WARN and returns, telling the agent nothing at all.

There is no refusal frame in `ServerMsg`, so the agent waits for a netmap that will never
arrive. **A device that cannot get an address is indistinguishable from one that is simply
offline** — including to the operator looking at the dashboard.

### 1c. Roughly half of the oldest org's issued ordinals belong to no document

`100.65.4.0/22` has issued 35 ordinals. 17 are held by live nodes and 1 sits in `free_hosts`.
The remaining ~17 are orphans: released before the recycle pool existed, with nothing to
return them to. No eviction path can reach them, because they belong to no row.

On a `/22` (1 022 usable) that is survivable. The *rate* is the point — it is the org that
has been running longest, and half its issued space has leaked.

### 1d. The two legacy networks are not the same problem

Read before starting P4, and it changed P4:

| network | tenant | nodes | versions | status | last write |
|---|---|---|---|---|---|
| A | **row does not exist** (`9bc1…4472`) | `mbb-mars` `.1`, `mbb-zeus` `.2` | `0.3.0-rc.209` | both offline | 2026-07-23 |
| B | `demo` | 5 nodes, `.1`–`.5` | 0.4.37–0.4.40 | all online | live |

The overlap is concrete: `mbb-mars` and `macbook-pro` both hold `100.64.0.1`.

**A is not migrated, it is cleaned up.** Its tenant row is gone, so there is no
org to migrate and no admin to authorise it, and its agents sit *below* the
`0.3.0-rc.301` floor — a renumber would refuse without `--force` even if one
made sense. ⚠️ It also points at a cascade gap: §13 of `docs/multi-org.md`
records that there is **no tenant-delete route at all**, yet this tenant is gone
and left its network, nodes and addresses behind. Whatever removed it did not go
through `release_overlay_node`.

**B migrates cleanly** — every device is online and far above the floor, so
`below_floor` is empty and no `--force` is needed.

### 1e. What is NOT broken — a correction worth recording

An earlier assessment of this area claimed the allocator had no per-block ceiling and would
bleed into a neighbouring block. **That is false, and was false when it was written.**
`allocate_host` takes `max_host`, rides the bound on the atomic filter
(`next_host` must be `$lte max_host`), returns a loud `DaoError::Validation` on exhaustion,
and discards a pooled ordinal that sits above a since-shrunk ceiling rather than issuing it
(`crates/services/src/dao/overlay_network.rs:250-310`). The test
`allocate_host_stops_at_the_block_ceiling` locks it. Treat "1 022, then it refuses" as
verified behaviour.

## 2. What already exists — the parts this FR must not rebuild

Anchors verified against master at `201e3f5a`:

| Mechanism | Where |
|---|---|
| Lock-free global slot registry — monotonic, buddy-aligned, unique `slot`, `DuplicateKey` retry | `crates/services/src/dao/overlay_block.rs:81-150` |
| Variable width `/16` to `/22`; 4 032 slots above the legacy `/16` reserve | `crates/remote_control/src/models.rs` (`block_slots_for_prefix`, `OVERLAY_BLOCK_FIRST_SLOT`) |
| `Quarantined` to `Reclaimed`; `take_reclaimed` as the **exhaustion fallback only** | `dao/overlay_block.rs:170-250` |
| `POST /api/admin/overlay-block/reclaim` — dry-run, age gate, live-occupancy gate | `crates/api/src/routes/overlay_block.rs:866+` |
| `headroom { total, used, burned, reclaimed }`, with two readers | `dao/overlay_block.rs:300` |
| Renumber planner — ordinal preservation, capacity refusal, version floor, WS cycle | `routes/overlay_block.rs:183-255`, `:374+` |
| Per-address v6 derivation, so blocks follow for free | `overlay::router::derive_overlay_v6(Ipv4Addr)` |

## 3. Key design

### 3a. Carving becomes the default (P1)

Flip `blocks_enabled` and set it **explicitly** in the prod configmap. Existing networks are
untouched by construction: `ensure_block`'s virginity guard (default CIDR **and**
`next_host <= 1` **and** an empty pool, `dao/overlay_network.rs:120-131`) refuses to re-base
a network that has already leased anything. Migrating a populated network stays the
renumber endpoint's job.

⚠️ `ensure_block` **falls back to the shared `/10` when a carve fails**, at
`tracing::error!` (`dao/overlay_network.rs:139-148`). That is the right availability trade —
never fail a join over address bookkeeping — but it degrades isolation silently to anyone
not reading logs. This FR wires that line to an alert and adds a `headroom` threshold, so
the fallback stays a monitored condition instead of a quiet regression.

### 3b. Refusal becomes a frame, in one release (P2)

Add `ServerMsg::OverlayJoinRefused { reason, detail }`.

**This is a single-release change, and the reasoning is load-bearing.** An unknown
*top-level* `ServerMsg` variant fails `serde_json::from_str` on a fielded agent and is
absorbed by the existing "ignoring non-rc:* frame" `Err` arm — no panic, no fatal exit. That
is not an assumption: `pre_rc53_server_msg_rejects_goodbye_so_agent_err_arm_fires` in
`crates/remote_control/src/signaling.rs` asserts exactly it, and fires if anyone ever adds
`#[serde(other)]` and changes the behaviour.

The trap that *does* need a forward-compat pre-roll is a new variant of a **nested** enum
inside a frame the old agent already parses — the `RelayStrategyWire` case, where an unknown
tag fails the *whole enclosing `ServerMsg`* and the agent silently drops entire netmaps
(`signaling.rs:5139-5155`, `relay_strategy_lenient`). `OverlayJoinRefused` is not that shape.

### 3c. Multi-block per org (P5) — the growth mechanism

An org's address space becomes an **ordered, append-only list of blocks** rather than one
CIDR. Ordinals are assigned over the *concatenated* space (`1..1022` to block 0, `1023..` to
block 1), which is what keeps every existing `free_hosts` entry valid: blocks are
quarantined, never removed from the middle, so the list only ever grows at the tail.

Four consequences, each a sub-phase:

1. **`BlockList`** in `remote_control::models` generalizing `overlay_ip` / `overlay_host`
   into `ip_for_ordinal` / `ordinal_for_ip`.
2. **The registry's one-block invariant goes.** The partial unique index on `network_id`
   scoped to assigned rows (`crates/db/src/indexes.rs:328-331`) *is* that invariant, so it
   is dropped. It must be dropped before any second block can be allocated, and is
   effectively one-way afterwards.
3. **Allocation extends instead of refusing.** `allocate_host`'s ceiling becomes the sum
   across assigned blocks; exhaustion carves another block. P2's refusal frame then fires
   only for the genuinely terminal case — a full registry.
4. **The wire stays backward-compatible by making `cidr` per-recipient.**
   `OverlayNetworkInfo` gains `cidrs: Vec<String>` (`#[serde(default)]`), and the existing
   `cidr` field carries **the block containing that recipient's own address**. The netmap is
   already shaped per recipient, so this costs nothing structurally.

   Why it works: a fielded agent uses the network CIDR in exactly three places — the TUN
   netmask (`crates/tunnel-core/src/overlay/runtime.rs:2099`), the subnet-router NAT source
   scope (`:2087`), and change detection (`:3662`). All three are correct for an agent that
   is told *its own* block, and peers in other blocks are reached through the per-peer
   `/32`s the agent already installs. ⚠️ This is the compatibility claim the whole phase
   rests on, and it is to be **tested against a pinned old-agent decoder**, not argued.

### 3d. Orphan reclamation (P3)

An admin reconcile that enumerates `1..next_host`, subtracts ordinals held by **live** nodes
and those already pooled, and routes every gap back through
`OverlayNetworkDao::release_host` — never by writing `free_hosts` directly, so the
`$addToSet` de-dupe, the `next_host > host` guard and the `MAX_FREE_HOSTS` cap all still
apply. Dry-run by default, mirroring the block-reclaim route.

Running it twice, a month apart, answers a question nobody can currently answer: whether the
leak is purely historical or still active.

## 4. Phases

| # | Phase | State | Kill switch |
|---|---|---|---|
| **P0** | Spec + ledger row + issue | ✅ shipped | — |
| **P1** | Carving on by default; configmap key; carve-failure alert + `headroom` threshold | ✅ shipped + **field-verified** | `overlay.blocks_enabled` |
| **P2** | `OverlayJoinRefused` frame + `mh status` surface | ✅ shipped | additive; frame is ignorable |
| **P3** | `reconcile-hosts` admin route | ✅ shipped + **run against prod** (17 ordinals reclaimed) | dry-run default |
| **P4** | Migrate `demo`; clean up the orphaned network | ✅ done — the legacy `/10` holds no live node | existing renumber runbook |
| **P5a** | `BlockList` — the ordinal↔address model | ✅ shipped | — |
| **P5b** | Block list ordered by an explicit `seq` | ✅ shipped | — |
| **P5c** | A full network grows instead of refusing | ✅ shipped, **dark** | `overlay.multi_block_enabled`, default off |
| **P5d** | The wire: `cidrs` + per-recipient `cidr` | ✅ shipped, **dark** | same flag |
| **P5e** | Per-block NAT scope (Linux + Windows) | ✅ shipped, **dark** | same flag |
| **P6** | Docs | ✅ this file + `multi-org.md` §4.2 | — |

### What is NOT field-verified

⚠️ **A real pre-P5d agent BINARY meshing against a multi-block org.**
`overlay_growth_tests` proves the *server* shapes the netmap correctly — the
1023rd device grows the org over a real WebSocket, is told its own block, and
costs the first 1 022 nothing. It cannot prove an *old daemon* sizes its TUN
netmask and NAT scope correctly from that string. That needs an old binary
against a grown org, and until it is run, multi-block should stay off.

⚠️ **No org has ever actually grown.** The largest holds 17 devices against a
1 022 ceiling, so P5a–P5e is capability built ahead of need. That is why every
phase of it is behind one flag that is off.

## 5. Acceptance criteria

- [ ] A newly created organization receives a disjoint block with no operator action.
- [ ] Two organizations can never be issued overlapping ranges — asserted by test, and by
      the absence of any `100.64.0.0/10` network in production.
- [ ] A device that cannot be allocated an address receives a stated reason, and
      `mh status` shows it.
- [ ] An org that fills its block is given a second one; no device changes address.
- [ ] A pre-P5 agent meshes correctly against a multi-block org — verified with a real old
      binary, not a decoder test alone.
- [ ] The ~17 orphaned ordinals in `100.65.4.0/22` are returned to its pool.
- [ ] Both legacy networks are migrated; `100.64.0.0/10` holds no live node.
- [ ] Registry `headroom` is alerted on, and the shared-`/10` carve-failure fallback pages.

## 6. Open decisions

- Default carve width stays `/22` (1 022 devices, 4 032 orgs). With multi-block landing in
  P5, growth no longer argues for buying width up front, and the largest org in production
  holds 17 devices.
- Whether `reconcile-hosts` should also run on a schedule, or stay operator-invoked. Decide
  after the second manual run tells us whether the leak is ongoing.

## 7. Out of scope

- Reclaiming the legacy `/10`'s pre-release gaps. Those belong to no document *and* to a
  range that will hold no live node after P4; the `/16` reserve stays reserved permanently.
- Changing the quarantine-by-default policy for freed blocks.
- IPv6 as an independently allocated space — it stays derived per address.

## 8. Field-verification log

| date | version | what was verified | result |
|---|---|---|---|
| 2026-08-31 | prod | Carving off; 2 of 4 networks on the shared `/10` with overlapping addresses; ~17 orphaned ordinals in the oldest carved org | recorded in §1 |

### The state this FR opened on, and the state now

| | before | after |
|---|---|---|
| networks on the shared `100.64.0.0/10` | **2, holding overlapping addresses** | **0** |
| live nodes on `100.64.x` | 7 | **0** |
| orgs with a disjoint block | 2 (both hand-migrated) | **all of them** |
| carving for a new org | off; nobody opted in | **on by default, field-proven** |
| leaked host ordinals in the oldest org | ~17, unreachable | **0** |

`mbb-mars` and `macbook-pro` both held `100.64.0.1`. That is gone, and so is the
mechanism that allowed it.

Two bugs the work surfaced that were not in the original plan, both fixed:

- **A tenant row can be deleted outside the owner-only `archive` path**, leaving
  its overlay network, nodes and agents behind — that orphan is what produced
  one of the two overlapping networks. The instance is cleaned up; the CAUSE is
  not, and deserves its own FR.
- **`ensure_indexes` tolerated only `IndexNotFound` (27)** when dropping the
  one-block guard, not `NamespaceNotFound` (26). 26 is every fresh database, so
  multi-block would have worked on every environment it was developed against
  and broken the first clean production install.
