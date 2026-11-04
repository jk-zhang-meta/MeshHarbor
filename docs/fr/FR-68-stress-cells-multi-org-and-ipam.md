# FR-68: Stress cells for multi-org guard contention and IPAM growth

**Status**: shipped and field-verified — **every AC met except AC2**, which is
deliberately deferred (see "Is AC2 worth its cost?"). All PRs merged, both
repos. · **Owner**: overlay/networking ·
**Issue**: [#1272](https://github.com/jk-zhang-meta/MeshHarbor/issues/1272)

## Goal

Turn two overlay properties from **promises into properties**:

1. **FR-47's growth half can come out of the dark.** `overlay.multi_block_enabled` is
   `false` because its P5d wire-compatibility claim was never tested. FR-47's own spec says
   it "must be tested against a pinned old-agent decoder, not argued"
   (`docs/fr/FR-47-overlay-multi-block-ipam.md:169`). Until that exists, an org that reaches
   1 022 devices is refused an address.
2. **A #1237-class multi-org route war becomes catchable before the field.** It is fixed
   (`57cc7223` / #1246, shipped 0.4.51), but nothing in CI or the VM matrix would catch the
   next one — FR-61's matrix is single-tenant by construction.

## Evidence (why this exists)

- **#1237 ran for weeks in the field.** Two per-org runtimes evicted each other's
  `fd72:6f6f:6d6c::/96` on every guard wave: ~100 carrier revalidations/min, **718
  evictions/day on neo16**, CORPLAP-3 the v4 twin. Nothing failed; it was pure waste plus
  demoted real carriers.
- **The same shape against a third party is unbounded.** Our guard evicted Cisco
  AnyConnect's route mirrors **25,197 → 33,294 in one day** while Cisco re-added within
  milliseconds. Neither side holds the FIB and nothing yields (§ auto-yield below).
- **The matrix cannot see either.** FR-61 has one `VMTEST_TENANT_ID` and one
  `VMTEST_EPHEMERAL_KEY`; every guest driver performs exactly one enrollment. There is no
  multi-org cell and no IPAM cell — verified by exhaustive grep, not assumed.
- **`multi_block_enabled` has never run anywhere but a unit test.** Its one e2e
  (`crates/tests/src/overlay_growth_tests.rs`) fakes the scale with a cursor jump and says
  so in its own header; it cannot prove an *old daemon* sizes its netmask and NAT scope
  correctly from the string the server sends.

## Key design (anchors verified against `origin/master` @ `b91a7404`)

### Three layers, cheapest first

**L1 — in-repo tests.** Most of the IPAM risk is closable without a VM:

- **The decoder pin.** No test feeds a P5d netmap *containing* `cidrs` into a pre-P5d
  decoder. `a_pre_p5d_netmap_still_decodes_and_carries_no_block_list`
  (`crates/remote_control/src/signaling.rs:9956`) only tests old-server → new-decoder.
  Copy `agent-v0.4.42`'s `OverlayNetworkInfo` verbatim as a local struct and decode a real
  grown-org netmap into it.
- **Cross-tenant carve racing a grow.** `allocate`'s `DuplicateKey` arm
  (`crates/services/src/dao/overlay_block.rs:216`) is single-block-shaped: with multi-block
  the `network_id_1` index is dropped, so a `DuplicateKey` can only mean *another tenant
  took the slot* — yet the arm returns the network's existing block, the grow is a silent
  no-op, and the joiner is refused `AddressSpaceExhausted`.
- **Renumber-after-grow `seq` collision.** The renumber route
  (`crates/api/src/routes/overlay_block.rs:538-552`) uses the **singular**
  `find_assigned_for_network` and stamps `seq: 0`; `crates/db/src/indexes.rs:408` is a
  plain, non-unique `{network_id, seq}`. A tie on the sort key silently re-points every
  ordinal above it — the exact failure `seq` exists to prevent.
- **The one-way door.** `ensure_indexes(db, false)` after a network holds two assigned
  blocks must fail loudly (`crates/db/src/indexes.rs:17-21`). Untested.
- **Grow-while-live.** `OverlayNetmapDelta` carries no network info
  (`crates/api/src/ws/overlay.rs:652-674`), so a live subnet router never learns the space
  grew; its NAT scope stays block-0-only until the runtime restarts. Assert the bound.

**L2 — two VM cells** (FR-61 matrix, dedicated vmtest orgs, destructive).

**L3 — fleet, read-only.** Two `mh peers --json` + `mh status` snapshots ≥30 s
apart on the real multi-org Windows hosts (neo16, CORPLAP-3). No mutation, no VPN cycling,
nothing on prod cluster nodes.

### Why each cell lands on the lane it does

- **Multi-org ⇒ win11.** `defend_self_route` is **Windows-only**
  (`crates/tunnel-core/src/overlay/tun.rs:2663-2719`; no-op default at `tun.rs:95`). An
  Ubuntu cell would pass vacuously.
- **IPAM ⇒ ubuntu.** The pre-P5d degradation is in NAT *scope* — which CIDRs get a
  MASQUERADE rule (`crates/tunnel-core/src/overlay/nat.rs:119-133`) — which is
  platform-independent, and the ubuntu lane is the cheaper driver.

### What actually breaks on a pre-P5d agent (narrower than assumed)

A pinned old agent receives its **own** block in the per-recipient `cidr`
(`crates/api/src/ws/overlay.rs:623-626`), so netmask, per-peer `/32` routes and
`set_local_scope` are all **correct**. Unknown *fields* are silently ignored — there is no
`deny_unknown_fields` anywhere in `crates/remote_control` or `crates/tunnel-core`. Unknown
*variants* are fatal to the whole `ServerMsg` parse, but `agent-v0.4.42` already carries
`OverlayJoinRefused`, and the server gates that send on `supports_join_refusal` anyway.

The one real degradation: **a pre-P5d subnet router masquerades only its own block**, so
traffic from block 1 to a LAN behind a block-0 router black-holes one-way, silently.

⚠️ The genuinely catastrophic shape is a **pre-P5d SERVER** against a grown org with
**mixed prefixes** (`/16` block 0 + `/22` block 1): the node computes a connected prefix
that swallows other tenants' blocks. Uniform `/22` survives a rollback by accident.

### The two gaps in #1246's shipped fix, closed here

**C2(a)** `foreign_in_block_fp` (`tun.rs:816-820`) still reads
`r.InterfaceLuid.Value == ours` where its three siblings were converted to
`route_belongs_to_us` (`tun.rs:681`, `:755`, `:867`). #1246's commit message claims all four
were converted; three were. A sibling org's peer churn therefore flips the in-block debounce
fingerprint and triggers a full FIB walk that deletes nothing — the anti-flap guard defeated
on exactly the multi-org host it was written for.

**C2(b)** FR-64 C2 specifies "a WARN when two orgs' blocks overlap". It was never
implemented (`grep -i overlap` over `tun.rs` and `agents/meshharbord/src/overlay.rs` finds
nothing). With nested blocks — a legacy `/10` primary beside a carved `/22` secondary —
`defended_ula_prefix` (`tun.rs:1773-1791`) produces **nested, not disjoint** v6 prefixes and
the war can silently re-open.

⚠️ A WARN is a detector, not a fix. It makes the condition attributable instead of silent —
the argument FR-33's `lan` line won on. The structural fix (refuse to carve a block nested
inside a live one) belongs to FR-47's reconciler, not here.

### The assertion surface does not exist yet (C1)

There is **no counter** for route evictions or carrier revalidations. Both are log-only,
throttled to **1 WARN/min/prefix** carrying `suppressed_since_last` — a naive `grep -c`
under-reports by up to 40×. Three cumulative counters, following the canonical path
`crates/tunnel-core/src/evidence.rs:36-37` → `crates/localapi/src/lib.rs:227` →
`agents/meshharbor-cli/src/localclient.rs:1381-1387`:

`ROUTE_EVICTIONS` (split `sibling` / `foreign`) · `ROUTE_WAVES` · `FORCED_REVALIDATIONS`

Cumulative, printed only when non-zero, carrying the "DIFF two readings" note.

### Auto-yield is still gated to metric-0 — noted, not fixed here

The per-prefix strike counter and the `keeps DISAPPEARING` WARN are generalised to every
metric (`tun.rs:488-528`), but the **yield latch is hard-gated on `metric == 0`**
(`tun.rs:517-527`) and metric-0 is default-OFF, so on the fleet the latch is dead code.
A metric-1 war — Cisco's, or #1237's — can never self-limit. Out of scope here; recorded so
the next reader does not assume back-off exists.

## Phases

| # | Phase | Kill switch |
|---|---|---|
| P0 | Claim FR-68 (spec + ledger row, same commit) + issue | — |
| P1 | L1 in-repo tests | n/a (tests only) |
| P2 | C1 — three cumulative counters; field-verify on neo16 + CORPLAP-3 | read-only instrumentation |
| P3 | C2(a) predicate swap · C2(b) overlap WARN | `OVERLAY_SIBLING_EXEMPT` (a); WARN-only (b) |
| P4 | Harness two-tenant plumbing + full 18-cell regression run | `VMTEST_TENANT_ID_B` absent ⇒ cells NA |
| P5 | The two cells, incl. the `multiorg-control` negative control | the cell tuples |
| P6 | L3 fleet read-only arm | — |
| P7 | Handover; decide on `multi_block_enabled` | the flag itself |

## Acceptance criteria

- [ ] **AC1** A pre-P5d `OverlayNetworkInfo` decodes a real grown-org netmap without error
      and ignores `cidrs` — proven with the struct copied verbatim from `agent-v0.4.42`.
- [ ] **AC2** A real `agent-v0.4.42` daemon meshes in a grown org, and its **subnet-router**
      limitation is demonstrated rather than assumed (block-1 → block-0-router LAN).
- [ ] **AC3** A cross-tenant carve racing a grow does not silently refuse the joiner.
- [ ] **AC4** Renumber against a grown org does not duplicate a `seq`.
- [ ] **AC5** `ensure_indexes(db, false)` after growth fails loudly.
- [~] **AC6** (half — counters live and read on 3 hosts; the `spared` half needs a multi-org host) `ROUTE_EVICTIONS` / `ROUTE_WAVES` / `FORCED_REVALIDATIONS` are live and were
      read on two real multi-org hosts, **as a diff of two readings**.
- [x] **AC7** With C2(a)+C2(b), a two-org Windows guest shows **zero sibling evictions**
      over a sustained window.
- [x] **AC8** The negative control (`OVERLAY_SIBLING_EXEMPT=0`) **reproduces** the war —
      i.e. AC7 is not passing vacuously.
- [ ] **AC9** A nested-block pair (legacy `/10` primary + carved `/22` secondary) emits the
      overlap WARN.
- [x] **AC10** The 18 pre-existing vmtest cells are unchanged by the two-tenant plumbing.

## Open decisions

- Whether `multi_block_enabled` flips on after P5, or waits for a real org to approach its
  ceiling. Largest org today is 17 devices against 1 022.
- Whether the mixed-prefix (`/16` + `/22`) shape should be **refused at grow time** rather
  than merely tested — it is the only shape where a server rollback is catastrophic.

## Out of scope

- Generalising auto-yield beyond metric-0 (its own FR — see above).
- The structural fix for nested blocks (FR-47 reconciler).
- The pump-loop stall detector and the other items from the blocking-work analysis.
- Anything that mutates grox / demo / jovanov: the fleet arm is **read-only**.

## Where this stands — handover, 2026-09-03

### Shipped (branch `fr68-stress-cells`, PR #1273 — not merged)

| Commit | What |
|---|---|
| `a604490c` `325b2f2a` | FR claimed (spec + ledger row in one commit), issue linked |
| `a35720b6` | P1 — pinned pre-P5d decoder test (unit) |
| `182a4121` | P1 — same claim against a **server-produced** netmap (e2e) |
| `044f08f2` | P1 — one-way door: `multi_block` off after a grow fails the boot |
| `293d35a0` | C1 — four route-guard evidence counters |
| `dbf548b9` | C2 — `foreign_in_block_fp` predicate + the overlap WARN |

Deploy repo, branch `fr68-vmtest-cells` (pushed, no PR yet): `129c33e` — the
two-tenant plumbing.

### The finding that should change how the rest is scoped

**The pre-P5d blast radius is much smaller than FR-47 assumed.** An old agent is
sent its OWN block in the per-recipient `cidr`, so its netmask, its per-peer
`/32`s and `set_local_scope` are all correct, and unknown *fields* are ignored
(no `deny_unknown_fields` anywhere in `remote_control`/`tunnel-core`). The only
real degradation is a pre-P5d **subnet router**: it masquerades one block, so
traffic from block 1 to a LAN behind a block-0 router black-holes one-way,
silently. Ordinary peer-to-peer overlay traffic in a grown org is unaffected.

⇒ The IPAM cell only needs to cover the **subnet-router** role. A plain node
proves nothing that `a35720b6`/`182a4121` do not already prove.

### What is left, in order

### ⚠️⚠️ The IPAM cell CANNOT run against production — verified, not assumed

Growth is gated server-side on `overlay.multi_block_enabled`
(`crates/api/src/ws/overlay.rs:393`). The prod configmap
(`k8s/base/configmap-meshharbor2-config.yaml:62`) sets
`MESHHARBOR__OVERLAY__BLOCKS_ENABLED: "true"` and **sets `MULTI_BLOCK` nowhere**, so
production runs the code default `false`. Turning it on is a **one-way door for
that database**: once any network holds two assigned blocks the
one-block-per-network index cannot be recreated and the boot fails loudly —
which `044f08f2` now proves rather than assumes.

So the plan as approved was circular: it wanted to verify growth on the org
whose server has growth switched off, and the switch is the thing the
verification exists to license.

**~~Resolution — the `e2e` overlay.~~ ⚠️ RETRACTED 2026-09-04 — do NOT use it.**
`k8s/overlays/e2e` is a complete, separate, non-ArgoCD-managed stack, which is
why it looked right. But measured on the cluster: the `meshharbor-e2e`
namespace is **live and 120 days old**, and a **cron job runs against it nightly
at 03:30 UTC** (`e2e-nightly.sh` out of `~/wt-e2e-lane`, FR-37). It is a
standing shared dependency, not a scratch stack.

Putting a **one-way door** on someone else's nightly lane is a bad trade: if the
flag is ever set back to `false`, `ensure_indexes` refuses the boot by design
and the e2e stack simply stops starting, with a failure that reads as an
unrelated boot error. (Its mongo is `emptyDir`, so the door resets on a pod
recycle — that lowers the severity but does not make it someone else's stack to
change.)

**Use a separate disposable namespace instead** — `meshharbor-ipam`, copied
from the e2e overlay as a template (it already has ephemeral storage and
plaintext secrets, both of which suit a throwaway). The door is then confined to
a database that exists only for the test.

⚠️ The cell also needs `VMTEST_SERVER` to be per-cell rather than global —
currently one value in `lib.sh:18`.

### ⚠️ Is AC2 worth its cost? An honest read before anyone builds it

The IPAM VM cell uniquely proves ONE thing: that a real pre-P5d binary acting as
a **subnet router** in a grown org black-holes block-1 traffic one-way. Note
what is already closed without it — the pinned decoder accepts a real grown-org
netmap (unit + e2e), the netmask it derives is correct, and the one-way door
fails loudly. The remaining gap is NAT *scope* with real traffic, and the
mechanism is not in doubt: `nat::enable` took a scalar `overlay_cidr`, so one
MASQUERADE rule.

Against that: a new k8s stack, an org, an anchor, a guest driver and a cell.

And the population it protects is **currently zero** — `multi_block_enabled` is
off everywhere, so no org has grown, so no pre-P5d subnet router can be in a
grown org. The largest org today is **17 devices against a 1 022 ceiling**.

⇒ Recommendation: **defer AC2 until an org actually approaches its ceiling**,
and treat the L1 tests plus the documented mechanism as sufficient to enable
`multi_block_enabled` for a single org that needs it. Build the cell when the
first org gets close — the risk it covers does not exist until then. This is a
judgement, not a blocker: the plumbing notes above make it a day's work whenever
it IS wanted.

**The per-cell plumbing is smaller than it looks, with one trap** (checked
2026-09-04, so the next session need not rediscover it):

- Every consumer reads `VMTEST_SERVER` / `VMTEST_TENANT_ID` /
  `VMTEST_EPHEMERAL_KEY` as plain shell variables, and each cell script is its
  OWN process that sources `lib.sh`. So a cell that needs a different server
  just re-assigns them at the top of its branch — **no `lib.sh` refactor**.
- ⚠️ **`api_login` caches `API_TOKEN` and early-returns** (`lib.sh:146-148`).
  Re-assigning `VMTEST_SERVER` without also clearing `API_TOKEN=""` sends the
  OLD server's bearer to the new one — an auth failure that reads like a
  permissions problem rather than a plumbing one.
- ⚠️ The run-level teardown baseline in `vmtest.sh` is taken against the
  ORIGINAL server, so it cannot see rows the IPAM cell creates elsewhere. That
  cell must delete its own rows, the way the multi-org cell already deletes
  org B's (`teardown-b`).

Remaining cost is the stack itself, not the harness: an `e2e` deployment
carrying `MESHHARBOR__OVERLAY__MULTI_BLOCK_ENABLED: "true"`, plus an org and an
anchor on it.

The multi-org cell has no such problem: it needs two orgs, not a server flag,
and can run against prod.

**P5 — the two cells.** Blocked on nothing but work + a harness run.
- `guest/win-lane.ps1`: extend `[ValidateSet('system','attended','user')]` with
  `multiorg`; `lanes/win11/cell.sh:110` lifting loop gains `multiorg-mesh`,
  `multiorg-noevict`, `multiorg-control`.
- `guest/linux-lane.sh`: an `ipam` branch; `lanes/ubuntu/cell.sh:79` gains
  `ipam-grown`, `ipam-router`, `ipam-pinned`.
- Add the tuples to `vmtest.sh` `default_cells` **last** — they were
  deliberately withheld from `129c33e` because the lane scripts reject an
  unknown `--type`, and advertising a cell with no driver breaks a matrix run.

⚠️ **The guest sequence must resolve two rules that collide.** Flipping
`overlay_multi_org` requires a daemon restart (`org_join.rs:98-102,208-233`),
while FR-51 says never SIGTERM an ephemeral daemon — it self-unenrolls and its
row is deleted. Resolution: write the FULL config (both enrollments + the flag)
*before* the daemon's single clean start. install → stop the auto-started
configless service → enroll primary → enroll `--label b` → set flag +
`org overlay b tun` → **one** clean start.

⚠️ **The negative control is a PASS, not an expected failure.**
`expected-failures.txt` is an exact result-id match; putting an intentionally
inverted cell in it would rot the ledger. `multiorg-control` re-runs with
`OVERLAY_SIBLING_EXEMPT=0` / `OVERLAY_V6_DEFEND_NARROW=0` and passes **when the
eviction counter climbs**. A cell whose control does not reproduce the war is
not measuring anything.

⚠️ `mh status --json` has **no per-org address field** — the overlay
address is top-level `.overlay_ip`. A multi-org cell needs a per-org assertion
surface that does not exist yet; the `route guard` counters (C1) are the
substitute.

**P6 — fleet arm (AC6).** Needs the C1 counters actually deployed; numbers that
have never moved are not evidence. ⚠️ **neo16's `jovanov` enrollment is DOWN**
(`server goodbye (AgentDeleted)`) — it needs a fresh enrollment token before it
is a multi-org host again. CORPLAP-3 is the other.

**Remaining P1 tests** (optional, lower value):
- Cross-tenant carve racing a grow. ⚠️ Resists a deterministic test: the bug
  needs an interleaving between `allocate`'s slot read and its insert, and
  there is no hook. The fix looks narrow — the `DuplicateKey` early return is
  only correct when `seq == 0` (a network's FIRST block); on a grow (`seq > 0`)
  a duplicate can only mean a slot race, so it must retry. That is a
  discriminator using a parameter the function already takes.
- Renumber-after-grow `seq` collision (deterministic, straightforward).

### Environment notes for the next session

- ⚠️ **WSL and Windows cargo share `target/` and thrash** — every switch forces
  a full ~11–13 min rebuild. Use a WSL-local `CARGO_TARGET_DIR` on ext4: 4m34s
  cold, seconds incremental.
- Integration tests need BOTH `MESHHARBOR__DATABASE__URL` and
  `MESHHARBOR__REDIS__URL` on this box; without mongo auth every test dies in
  ~0.03 s with `Command createIndexes requires authentication`.
- `mh ssh mars` is refused (policy off); `mh exec` works but
  re-splits argv, so multi-word commands need care.
- The deploy repo stores **LF** (`git ls-files --eol` → `i/lf w/crlf`); the
  Windows worktree is CRLF via `autocrlf`. `git cat-file -p` applies the smudge
  filter and will mislead you — use `git ls-files --eol`.

## Field-verification log

### 2026-09-03 — C1 counters live on the fleet (0.4.58). **AC6 half-met.**

Released `agent-v0.4.58`; three Windows hosts self-updated and were read:

| host | `route guard` line |
|---|---|
| neo16 | `evicted=0 spared=0 waves=8 revalidations=0` |
| CORPLAP-1 `CORPLAP-1` | `evicted=0 spared=0 waves=112 revalidations=10` |
| CORPLAP-3 `CORPLAP-3` | `evicted=0 spared=0 waves=56 revalidations=9` |

✅ The `evidence` → `localapi` → CLI path works end to end, and `waves` differs
per host by uptime, so these are measurements rather than a constant.

⚠️ **`spared=0` everywhere is a STRUCTURAL zero, not a pass.** No fleet host is
multi-org: neo16 **and** CORPLAP-1 both report `jovanov … disconnected: server
goodbye (AgentDeleted)`, and CORPLAP-3 has no second org. With no sibling
adapter there is nothing to spare, so **AC7 and the `spared` half of AC6 remain
unverified** — reading that zero as "no sibling war" would be mistaking absence
of the feature for absence of the fault. Closing it needs one host's second org
re-enrolled.

🔑 Notable: CORPLAP-3 runs AnyConnect — the client our guard historically fought
**25,197 → 33,294 evictions in one day** — and reads `evicted=0`. First time that
war has been measurable rather than inferred from a WARN throttled to
1/min/prefix. Not over-read: metric-0 defence is default-off and these daemons
had restarted.

### 2026-09-03 — the counter found something on its first day → #1282

neo16, idle, 0.4.58, three readings five minutes apart:
`waves 95 → 195 → 295` = **19.9/min then 20.0/min**, sustained.

The intended steady state is a 30 s heartbeat (~2/min); 20/min is *exactly* the
`ROUTE_WAVE_MIN_INTERVAL = 3 s` event-arm ceiling. CORPLAP-3 measured ~41/min.
`evicted=0` and `revalidations=0` throughout, so it is neither an eviction war
nor a cause of carrier churn — apparently pure wasted work, which is why nothing
ever surfaced it. No log line exists for it either. Filed as **#1282**.

### 2026-09-04 — the multi-org cell trio, all three green. **AC7 + AC8 met.**

Org B bootstrapped (`6a99ff01565641d3a027609e`; created on `free`, flipped to
`business` and read back). Three cells on zeus, each a throwaway Win11 guest
enrolled into TWO orgs, 120 s guard window:

| cell | evicted | spared | waves | establishes |
|---|---|---|---|---|
| `multiorg` | **+0** | +0 | +80 | healthy — narrowing keeps the adapters apart |
| `multiorg-narrow` | +0 | **+80** | +80 | the exemption IS load-bearing: one spare per wave |
| `multiorg-war` | **+67** | +0 | +80 | the pre-#1246 war reproduces |

Each run verified two adapters (`meshharbor` + `meshharbor-6a99ff0`) and dumped
`org ls` and every `fd72:*` route, so the numbers are anchored to an observed
topology rather than a bare PASS.

🔑 The route table is the mechanism, visible per mode:
- healthy → `…:1400/118` and `…:1c00/118`, **no `/96` row at all**
- `narrow` → **two** `::/96` rows, one per adapter, both surviving
- `narrow+exempt` → **one** `::/96` row — they delete each other every wave

### ⚠️⚠️ Three corrections this trio forced, all to THIS cell

1. **The first `multiorg` PASS was vacuous and was reported as a result.**
   `enroll` appends every org entry with `overlay_mode: Off`, hardcoded
   (`agent-core/src/enrollment.rs`, with a test asserting it); `--overlay` sets
   the PRIMARY's `overlay_enabled` and cannot switch a secondary on. The
   sequence needs `meshharbord org overlay <label> tun` — which this FR's own plan
   specified and the driver never called. The guest came up with ONE adapter,
   so `evicted=0 spared=0` was a structural zero with no sibling to contend
   with. Caught only because the `narrow` control refused to reproduce.
   **The negative control found the bug in the positive cell.**

2. **`spared > 0` was the wrong assertion for a healthy host** (recorded
   2026-09-03): narrowing makes the prefixes disjoint, so the exemption is
   never consulted and `spared+0` is correct. Asserting otherwise would have
   failed every healthy host and passed only where the outer defence was broken.

3. **The `/96` receipt is mode-dependent.** Demanding two rows reported
   `multiorg-war`'s row collapse — *the war itself* — as "kill switch not
   applied". A guard that mistakes the phenomenon for a misconfiguration is
   worse than none, because it stops you looking.

🔑 And the env channel was never the problem. "The kill switch never reached the
daemon" was my hypothesis for two rounds; the route-table receipt disproved it
(`/96 asserted by 2 adapters`) before any change was spent on it.

### 2026-09-04 — full 20-cell matrix: **PASS 92 / fail 0**. AC10 met.

`pass=92 fail=0 na=12 total=119 unexpected=''` — the whole matrix, ~1.5 h on
zeus. **The two-tenant plumbing changed nothing for the 18 pre-existing cells**:
every Ubuntu and Win11 lane green across `install / enroll / overlay / wayland /
rd / desktop`, which is what the defaulted-tenant-argument shape was designed
for, now measured rather than argued.

All three multi-org cells reproduced independently inside the full run:

| cell | evicted | spared | waves |
|---|---|---|---|
| `multiorg` | +0 | +0 | +80 |
| `multiorg-narrow` | +0 | **+80** | +80 |
| `multiorg-war` | **+66** | +0 | +80 |

🔑 `multiorg-war` landing on **66** where the standalone run gave **67** is the
right kind of variance: eviction vs re-assertion is a race, so an exact repeat
would have been more suspicious than a near-miss. The other two are identical,
which is what a deterministic path should give.

The 12 NA are the by-design impossible combinations, and the 15 WARNs are the
best-effort `overlay-reverse` checks plus one teardown row awaiting the reaper's
TTL. ⚠️ `overlay-reverse` WARNs on every cell; it does not gate the verdict and
touches none of the changed helpers (it is `docker exec vmtest-anchor meshharbor
ping`), so it is a standing property of the anchor's reverse path to a fresh VM,
not a regression. No retained earlier run carries these lanes to compare
against — stated as reasoning from the code, not as a measured before/after.

### ⚠️ Method note — a cumulative counter that DECREASES means a restart

CORPLAP-1 read `waves=112 revalidations=10`, then `waves=56 revalidations=0`
minutes later: its daemon had restarted, and counters reset at process start.
"Diff two readings" is necessary but not sufficient — **a decrease invalidates
the diff**, and computing it anyway yields a confident negative rate. Check for
a decrease before trusting any delta.
