# FR-54: An organization can vanish and leave its mesh behind

> **CLOSED 2026-09-01** — issue #1130 is closed and its acceptance criteria are met. Any status line below is the state while the work was in flight, kept as the record.

**Issue:** [#1130](https://github.com/jk-zhang-meta/MeshHarbor/issues/1130) ·
**Status:** proposed · **Owner:** overlay/networking

## Goal

Data that outlives the organization it belongs to should be **findable**, not
discovered by accident three months later while reading unrelated tables.

## 1. Field evidence

Found on production 2026-08-31 while auditing overlay IPAM for FR-47:

```
overlay_networks → tenant_id 9bc122600e1dc12cb6ef4472
db.tenants.countDocuments({_id: that}) → 0
```

The tenant row was gone. Left behind, live and reachable by nothing:

| collection | rows |
|---|---|
| `overlay_networks` | 1 (on the shared `100.64.0.0/10`) |
| `overlay_nodes` | 2 (`mbb-mars` `.1`, `mbb-zeus` `.2`) |
| `agents` | 2, both `0.3.0-rc.209`, offline since 2026-07-23 |

⚠️ **It was not inert.** Those two nodes held `100.64.0.1` and `100.64.0.2`,
which is exactly what the `demo` tenant's first two devices also held — the
address collision FR-47 opened on was *caused* by an orphan nobody knew about.
A dead org's leftovers were actively colliding with a live one's.

## 2. Root cause — and a correction

**There is no tenant-delete code path.** Not one that bypasses `archive`; none
at all. `roles` and `rooms` have `delete_one` / `delete_many`; the tenant DAO
has only `set_archived`, and no route deletes a tenant. Verified by search
across the tree, not assumed.

So the row was removed by **hand, in MongoDB** — an operator or a script. That
correction matters, because it changes what is worth building: there is no
broken code path to repair. What is missing is any way to *notice*.

## 3. Key design

### 3a. Detect, do not enable

`POST /api/admin/overlay-network/orphans` — platform-operator only, **dry-run by
default**, mirroring the shape of `…/overlay-block/reclaim` and FR-47's
`…/reconcile-hosts` (which already share that gate, that default and that
response shape).

For each `overlay_networks` row whose `tenant_id` resolves to no tenant, report
the network's CIDR, its live node count, its backing agents, and the newest
`updated_at` — enough for an operator to tell a week-old accident from a
year-old experiment before deciding anything.

Applying releases the mesh through the **existing** teardown
(`ws::overlay::release_overlay_node`), never by deleting rows directly. The
guards in that path are the whole reason it exists: it tombstones under a CAS,
pools the host ordinal, and fans `netmap_delta{removes}` to peers. A cleanup
that bypassed them to tidy up would be the same class of act that created the
mess.

### 3b. Deliberately NOT a tenant-delete route

`archive` exists so an org can be retired **without** destroying its records,
and `docs/multi-org.md` §13 explains why. Adding a real delete would create a
destructive path where a deliberate design decision says there should not be
one, and would not have prevented this orphan anyway — whoever removed that row
was already working outside the API.

The goal is to make manual surgery **detectable**, not **supported**.

### 3c. Why a route and not a startup sweep

A sweep at boot would run on every pod, on a schedule nobody chose, against a
condition that should be rare — and would either log into the void or delete
without a human. Orphans are an *operator* question: how they got there matters
as much as that they are there.

## 4. Phases

| # | Phase | Kill switch |
|---|---|---|
| **P1** | The detector route, dry-run default, report only | dry-run |
| **P2** | Apply: release each orphaned node through `release_overlay_node` | dry-run |

## 5. Acceptance criteria

- [ ] A network whose tenant row is gone is reported, with node and agent counts
- [ ] A network whose tenant EXISTS is never reported, archived or not — an
      archived org is retired, not orphaned, and the two must not be conflated
- [ ] Applying releases nodes through `release_overlay_node`, so addresses
      return to the pool and peers are told
- [ ] Dry-run writes nothing, and a second run after an apply reports nothing

## 6. Out of scope

- A tenant-delete route (§3b).
- Orphans in other collections. Overlay networks are where this bit, and a
  detector that claims to cover everything while covering one thing is worse
  than one that names its scope.

## 7. Field-verification log

| date | what | result |
|---|---|---|
| 2026-08-31 | Orphan found during the FR-47 audit; 2 nodes colliding with `demo`; removed by hand after a backup | recorded in #1071 |
