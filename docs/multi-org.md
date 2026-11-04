# Multi-org devices, multi-user remote control, cross-org notifications

One machine enrolled in N organisations. N people controlling one host at the
same time. Events from every org reaching a user regardless of which org their
UI is parked on.

This document is the map of that program: what shipped, how the pieces fit,
what an operator has to do, how it fails, and what is still open. It assumes
familiarity with [`remote-control.md`](remote-control.md) (the RC subsystem)
and [`overlay-communication.md`](overlay-communication.md) (the mesh).

---

## 1. The problem

Before this work a meshharbor device was enrolled in exactly **one** org: one
config identity, one agent JWT, one WS, one overlay identity. Three
consequences, each of which real deployments hit:

1. **A contractor's laptop can't be in two fleets.** Re-enrolling REBOUND the
   config to the new org and silently evicted the old one.
2. **Two people can't work on one host.** The agent pinned
   `max_simultaneous_sessions` to 1, and five latent single-session
   assumptions made anything else unsafe.
3. **A user in three orgs sees events from one.** The UI fetches rooms,
   unread counts and device presence for the ACTIVE tenant only, so an alert
   from another org was invisible until you switched to it.

And underneath all three: **every tenant's overlay shares
`100.64.0.0/10`**, with each network's host cursor seeded at 1. Tenant A's
`100.64.0.7` and tenant B's `100.64.0.7` are literally the same address. That
is harmless while a daemon carries one org and fatal the moment it carries
two — one interface, one routing table, two claimants for the same `/32`.

## 2. Topology: ONE multi-tenant daemon

The alternative — N side-by-side installs — is structurally blocked, and it is
worth recording why so nobody re-proposes it:

- the TUN adapter has a fixed name and GUID, and the rc.279 adapter sweep
  pnputil-removes any non-Up `^meshharbor` adapter — sibling daemons delete each
  other's interfaces;
- two on-link `/10`s on one host are ambiguous, and each daemon's route guard
  purges what the other installs (a purge war);
- the LocalAPI pipe (`\\.\pipe\meshharbor`) is a singleton, as are the SCM
  service name and the scheduled-task name;
- exit-node split-defaults, NRPT DNS steering and WFP rules are all
  host-global;
- the updater is per-machine.

So: **one daemon, many orgs**. Everything below follows from that.

---

## 3. P1 — the foundation: `[[orgs]]` (shipped, #313)

The config's scalar identity stays the **primary** enrollment — a pre-multi-org
binary keeps serving it and never reads the new table, which is what makes an
MSI rollback safe. Additional enrollments live in an `[[orgs]]` array:

```toml
# primary (scalar, unchanged)
server_url  = "https://meshharbor.itachi.fans"
agent_token = "…"
agent_id    = "…"
tenant_id   = "…"

[[orgs]]
label        = "acme"
server_url   = "https://meshharbor.itachi.fans"
agent_token  = "…"
agent_id     = "…"
tenant_id    = "…"
enabled      = true
overlay_mode = "off"          # off | netstack | tun — P1 forces secondaries off
```

**Enrollment dispatch** (`apply_enrollment`):

| Case | Behaviour |
|---|---|
| same `(server, tenant)` | refreshes in place, keeping operator state |
| a NEW `(server, tenant)` | **appends** a secondary org with a freshly **minted** WG key |
| `--replace` | the legacy rebind, for when you really do mean "move this box" |

The fresh key mint is a security property, not an optimisation: copying the
primary's WG public key into a second org would let two orgs correlate the
same device by pubkey. `machine_id` IS reused across orgs — the server dedupes
per `{tenant_id, machine_id}`, so every org sees the same fingerprint and a
re-enroll finds the existing row.

CLI: `meshharbor org ls | rm | enable | disable | set-primary`, `enroll --label`,
`re-enroll --org <label>` (with a same-tenant guard).

**`org set-primary <label> [--demoted-label <name>]`** swaps a secondary into
the primary slot. Do this when the organization that should manage the machine
is not its primary. The primary drives the machine-wide effects:
- **the self-updater:** an `rc:agent.update` ("Update" or "Update all" in a
  secondary org's dashboard) is ignored, with a WARN. Since FR-67 P7 that
  dashboard says so before the click, and the server refuses the push with
  `primary_org` instead of counting it delivered;
- **attention sentinels;**
- **declared tunnel routes.**

The demoted primary moves into `[[orgs]]` under `--demoted-label`, or else under
the promoted org's old label. The change applies at the next daemon start.

⚠️ **Each enrollment keeps its place on the mesh where that maps exactly**
(#2540). Before this, a swap took both off, which multi-org P1 did on purpose
"until P2's per-org overlay lands". P2 landed, and a swap run to fix updates
then cost a two-org host its mesh path, measured on 2026-10-19.

| Before | After the swap | Why |
|---|---|---|
| the promoted secondary was `tun` | the new primary is **on** (its own OS TUN) | it already ran an OS TUN on this host |
| the promoted secondary was `netstack` | the new primary is **off** | a primary's netstack is the env key `MESHHARBORD_OVERLAY_NETSTACK_SOCKS`, which `overlay_multi_org` overrides; config cannot express it |
| the old primary was on, with `overlay_multi_org`, on the same control plane | the demoted entry is **`tun`** | it ran its own OS TUN; a `tun` org needs the primary's control plane |
| the old primary was on, without either | the demoted entry is **off** | `meshharbord org overlay <label> netstack` keeps it on |

The command prints the outcome for each enrollment, with the way back on where
it could not keep one.

**Per-org supervisors.** `run_cmd` starts one supervised loop per enabled org.
`OrgCtx` threads the per-enrollment identity through `run` / `connect_once` /
`handle_server_msg`, which buys:

- per-org watchdog pumps and per-org `DOWN_SINCE` outage stamps (this was a
  process-global static — org B reconnecting would erase org A's outage);
- a secondary's goodbye or duplicate-duel terminates **only its own loop**. A
  goodbye (`AgentDeleted` / `PolicyRejected`: the device was removed,
  quarantined or refused there) costs **one WARN per start**, naming the ways
  out: `re-enroll --org <label>`, `org disable <label>` (kept and reversible)
  or `org rm <label>`. The same text is the org's terminal status in
  `meshharbor status`. ⚠️ The daemon never drops the enrollment itself, because
  `AgentDeleted` also covers a quarantine that an admin can lift (#1750);
- invalid entries are skipped with a surfaced reason, never fatal.

**Primary-only, deliberately:** `rc:agent.update` (a secondary org's admin
must not be able to force-update a shared binary — the ignore is surfaced via
log + a LocalAPI counter), attention sentinels, exit-route purge, and
`process::exit` escalations. The updater polls the primary's server.

⚠️ **The server is told too (FR-67 P7).** Every announcement of an enrollment's
caps carries `update_mode`: `self` (the primary, with its updater on),
`primary_org` (a secondary: the push is ignored) or `off` (auto-update off: the
push is dropped). The server refuses a push the device will not act on: a 409 on
one device, a `refused` row with its `refused_code` in Update all. Before this,
a frame the device ignored had still reached its socket, so the dashboard counted
it delivered. An agent that predates the word is pushed as before.

LocalAPI grew `NodeStatus.orgs` (wire-locked; empty ⇒ omitted, so single-org
daemons stay byte-identical) and `RouteDescriptor.org`.

---

## 4. P2 — overlay tenant blocks

### 4.1 P2a: forward-compat (shipped rc.301, #314)

Four changes every agent had to carry **before** any tenant could be carved,
because the first renumber would otherwise brick mixed fleets:

- the boot reconciler's keep-set is prefix-aware: it keeps ANY on-link v4
  block inside the CGNAT `/10`. The old literal `100.64.0.0/` match would have
  purged a renumbered tenant's own connected route at every daemon start —
  host-wide mesh blackhole;
- IPAM is bounded by the network's own CIDR (`cidr_max_host`), so a busy
  tenant can never walk into its neighbour's block. Exhaustion is a loud
  error, never an out-of-block lease;
- netmap deltas process **removes before upserts**, and `install_peers`
  reinstalls on a changed `overlay_ip` under a stable key — pre-P2a a
  renumber's `remove(id) + upsert(id, new_ip)` pair netted to "peer gone";
- `dns::configure_os` is gated on `dns_bound` (steering the OS at a resolver
  that never bound `:53` blackholes the magic domain host-wide — NRPT is
  registry-global on Windows).

### 4.2 P2b: the registry + the migration (this phase)

**`overlay_blocks`** is a GLOBAL registry — deliberately not tenant-scoped,
because its whole job is guaranteeing two tenants never hold overlapping
slices of the `/10`.

- The grid is aligned runs of `/22` **slots** (1024 addresses). A block is
  `slot` + `slots` (a power of two, aligned).
- Allocation is **monotonic upward from slot 64 = `100.65.0.0`**. Everything
  below — the whole `100.64.0.0/16` — is reserved for legacy tenants, which
  all start at `100.64.0.1` and grow upward. A carved tenant therefore cannot
  collide with an unmigrated one no matter how many devices the latter leases
  (it would need 65 534 of them to reach slot 64).
- Non-overlap is **structural, not locked**: `slot` is uniquely indexed and
  starts are buddy-aligned, so two concurrent allocations either collide on
  the same slot (the index arbitrates; the loser retries above the winner) or
  claim disjoint ranges. The property is pinned by
  `aligned_starts_are_never_partially_overlapping`.
- Freed blocks are **quarantined, never re-issued**. A device that missed a
  migration (offline, or a stale binary) still believes it holds an address in
  the old range; handing that range to another tenant would give it a live
  neighbour's address. The row stays as the forensic record of who held it.

**Carve-on-create** is `overlay.blocks_enabled`, **default ON since FR-47**.
Setting it to `false` is the kill switch and is still exactly the pre-P2b
behaviour (the DAO then makes zero registry reads). Only a *virgin* network is
carved: re-basing a populated one under live nodes would leave every leased
address outside its own CIDR. Migrating a populated tenant is the renumber
endpoint's job, because only that path rewrites the node rows and cycles the
sockets.

⚠️ It shipped default-**off** for a staged rollout and then simply stayed off,
which quietly made isolation opt-in. Measured on production 2026-08-31: of four
overlay networks, two were still on the shared `100.64.0.0/10` and therefore
**held overlapping addresses** — both seeded at `.1`, so both owned
`100.64.0.1` and `.2`. The two carved networks existed only because someone had
renumbered them by hand. That is the exact collision class this registry was
built to make unrepresentable, surviving because the mechanism that prevents it
was never switched on. Hence the flip: a default that has to be remembered is
not a default.

⚠️ A failed carve does **not** fail the join — `ensure_block` falls back to the
shared `/10` and logs at ERROR with `alert = "overlay_block_carve_failed"`.
That is the right availability trade, but every tenant taking that branch is
seeded at `.1` and so overlaps every other one that did, which is why the
message names the consequence and why a fresh carve WARNs
(`alert = "overlay_block_registry_pressure"`) once the slot cursor passes 80%.

**Config:**

| Key | Env | Default |
|---|---|---|
| `overlay.blocks_enabled` | `MESHHARBOR__OVERLAY__BLOCKS_ENABLED` | `true` (FR-47; `false` = kill switch) |
| `overlay.block_prefix` | `MESHHARBOR__OVERLAY__BLOCK_PREFIX` | `22` (1022 devices; 4032 tenants fit) |
| `overlay.block_version_floor` | `MESHHARBOR__OVERLAY__BLOCK_VERSION_FLOOR` | `0.3.0-rc.301` |

### 4.3 The renumber runbook

```bash
TID=<tenant hex>;  TOKEN=<admin JWT>

# 1. Pre-flight. `below_floor` MUST be empty; `capacity` must exceed `nodes`.
curl -s -H "Authorization: Bearer $TOKEN" \
  https://meshharbor.itachi.fans/api/tenant/$TID/overlay-block | jq

# 2. Plan. This is the default — it writes NOTHING and consumes no block.
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{}' https://meshharbor.itachi.fans/api/tenant/$TID/overlay-block/renumber | jq '.new_cidr, .moves'

# 3. Apply, during a maintenance window (see the warning below).
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"dry_run":false}' https://meshharbor.itachi.fans/api/tenant/$TID/overlay-block/renumber | jq
```

What the apply does, in order: quarantine the old block → allocate the new one
→ rewrite every live node's `overlay_ip` → reset the network's cursor and clear
its free pool → cycle every agent's WS.

- **Ordinals are preserved** where they fit (`100.64.0.7` → `100.65.0.7`), so
  notes, `known_hosts` entries and dashboards stay readable. Ordinals past the
  new block — or addresses that don't parse under the old CIDR — are
  **compacted** onto the lowest free ordinal. The planner runs preservation as
  a first pass over the whole set, so a compacted node can never steal an
  ordinal a later node would have kept.
- **The version floor** refuses the apply and names the offending devices
  (a dry run still plans, so you can see the damage first). `force: true`
  overrides. Versions are compared numerically — `rc.99` sorts ABOVE `rc.301`
  as a string, which would have waved through exactly the fleet the gate
  exists to stop. An unknown/empty version fails **closed**.
- **The cycle is why this needs a window.** A node's `self_ip` binds once,
  when its overlay session establishes, so nothing short of re-establishing
  the socket makes a live fleet re-bind. The cycle rides the rc-ctrl lane
  (`overlay_cycle`), so it reaches whichever pod owns each socket. Unlike the
  rehome nudge it does **not** refuse a busy agent — a mesh in use has no idle
  moment to wait for.

> ⚠️ **Corp-VPN hosts.** A cycle tears the agent's rc/tunnel/overlay planes for
> seconds. A host behind a strict corporate VPN loses its established direct
> path and cannot re-punch while the VPN client is armed — it comes back
> **relay-locked** until a VPN-off window. Renumber those hosts deliberately.
> See the winhost-a notes in [`overlay-nat-traversal.md`](overlay-nat-traversal.md).

> ⚠️ **Tunnel-client nodes** are not hub-registered, so the server has no cycle
> primitive for them. They are listed in the response under
> `reconnect_required` and pick the new address up on their next reconnect.

### 4.4 P2c: the shared TUN (agent half) — deleted in W7c

> 🗄️ **History.** W7c (overlay v3) deleted the shared-TUN mux and the
> compensation stack around it, once its evidence counters (`mux_nat_rewrites`,
> `restores`, `skip_as_source_flips`) had read zero fleet-wide for 7 days. Every
> org now gets its own adapter ([Per-org TUN adapters](#per-org-tun-adapters-the-only-path-since-w7c),
> `agents/meshharbord/src/overlay.rs:318`). This section records how the mux
> worked, for the history it explains.

One `meshharbor` adapter, N per-org runtimes. Each org's `OverlayRuntime` gets a
`MuxPort` facade (`tunnel_core::overlay::tun_mux`) that looks exactly like its
own TUN; a single reader pump demuxes the real device's packets by
**destination, longest prefix first**. The demux table needs no netmap
plumbing — it is built from the very calls that install OS routes
(`add_peer_route` `/32`s, `add_cidr_route` subnet routes + exit
split-defaults, plus each org's own block from registration), so the OS table
and the demux table cannot drift. Derived-ULA v6 unmaps to its embedded v4;
non-ULA v6 (an exit client's egress) matches the installed v6 routes.

Enable it (default **off**):

```toml
overlay_multi_org = true          # or: meshharbor config set overlay_multi_org true

[[orgs]]
label        = "acme"
overlay_mode = "tun"              # + the org's own WG key, minted at enroll-append
```

The gate requires all of: the flag, `overlay_mode = "tun"`, the **same
`server_url` as the primary** (one control plane — the demux is only decidable
against blocks one registry carved), and the org's own WG key. The device
comes up with the first org's address; each later org's self-IP is added to
the adapter (`SystemTun::add_address_sync`), whose assignment carries the
block's connected route.

**Why P2b is the prerequisite:** a legacy `/10` org and any number of
carved-block orgs coexist (longest prefix wins, and carved blocks start above
the legacy reserve) — but **two un-migrated `/10` tenants are undecidable**,
and the mux refuses the second at registration (`AddrInUse`, warn-logged).
That org's overlay withholds until one tenant renumbers (§4.3); the other
orgs' meshes stay up.

Still primary-only, deliberately: **exit-node roles** (split-defaults and the
NRPT "." steer are host-global). A **secondary in netstack mode** runs its own
stack and SOCKS5 front (#2493), on the loopback port its `[[orgs]]` entry
names. It needs neither `overlay_multi_org` nor the primary's control plane,
because it opens no adapter and installs no route. Only the PRIMARY's env-key
netstack still yields to `overlay_multi_org`: with the flag on, the primary
uses its OS TUN regardless of `MESHHARBORD_OVERLAY_NETSTACK_SOCKS`.

---

## 4a. Multi-org v2 — the shared carrier plane (`overlay_shared_carrier`, default ON since rc.339)

Historically every org runtime bound its own direct sockets off the SAME
stable port base, deconflicted only by the blind band walk — so which org
held 43648 was a spawn-order race that re-ran on every restart and swapped
ports between orgs (NAT-mapping churn on the org that lost).

With `overlay_shared_carrier` on (`MESHHARBORD_OVERLAY_SHARED_CARRIER`,
config key `overlay_shared_carrier`), the daemon binds **ONE process-wide
socket set** (`crates/tunnel-core/src/overlay/carrier_plane.rs`) that every
org's engine attaches to:

- inbound is demultiplexed by the **WireGuard receiver index** (session
  indices are allocated plane-wide, unique across orgs), so two orgs'
  sessions arriving from the SAME remote `ip:port` — the post-migration
  normal when the peer is also multi-org — can never alias;
- handshake initiations (no index on the wire) route by per-engine
  static-key trial authentication, WireGuard's own model;
- ONE srflx gather / NAT probe / keepalive serves every org; each runtime
  still advertises on its OWN control WS after its OWN join (the server's
  join-clears-srflx ordering holds per org).

⚠️ **A plane socket's receive loop reads on past errors about an EARLIER
datagram** (#2220). Windows reports an ICMP port-unreachable for a datagram
the socket sent as `WSAECONNRESET` (10054) on the NEXT receive. Such datagrams
are ordinary: one to a peer whose daemon restarted onto another port, to a
stale endpoint, or a disco ping to a LAN candidate that is another host on
this LAN.

Before #2220 the loop ended on that error, and the socket stayed bound and
advertised with nothing reading it. Its direct paths sat on DERP until
something rebuilt the whole plane: 107 s in the field, via the srflx watchdog,
and never at all for a socket the keepalive doesn't ride. Defender Firewall's
default inbound rules drop that ICMP, which is why it took a host with the
firewall open to show it.

`crates/tunnel-core/src/overlay/udp_recv.rs` is the one classification,
shared with the per-device demux (`wg.rs`) and the MagicDNS resolver (#2213).
Only real OS sockets use it: a relay carrier reports a CLOSED session as
`ConnectionReset`, and reading on past that would spin.

Default ON since rc.339 (after the 4-host field soak: winhost-a + fleet-host-2 +
fleet-host-1 + buildhost, both flags, 08-08→08-10). Explicit `overlay_shared_carrier =
false` is the kill switch: per-runtime binds, byte-identical to the
pre-plane behavior, retained until the compensation-stack deletion.
Rebuilds under the flag are PLANE-WIDE (P1-d): any org's trigger
tears every org down (`Teardown`/ack, 3 s straggler timeout), the plane
re-binds ONCE, and every org re-establishes on `Ready`.

### Per-org TUN adapters (the only path since W7c)

The second half of multi-org v2: with `overlay_multi_org` on, each org gets its
**own adapter** (`per_org_systun_factory`, `agents/meshharbord/src/overlay.rs:318`).
It shipped behind `overlay_tun_per_org`, default ON since rc.339; W7c deleted
the switch along with the shared adapter it chose between, so neither the key
nor `MESHHARBORD_OVERLAY_TUN_PER_ORG` is read any more:

- the primary KEEPS the legacy `IF_NAME` (`meshharbor` on Windows, `meshharbor0`
  on Linux) + GUID (no adapter churn on the mode flip); a secondary is
  `<IF_NAME>-<tenant-prefix>` with a stable per-org GUID (`org_tun_guid` —
  SHA-256, RFC 4122-shaped). The tenant prefix is clamped to fit Linux's
  15-char `IFNAMSIZ` (Windows `meshharbor-` → 7 hex; Linux `meshharbor0-` → 6),
  so the secondary adapter name never overflows and the org's TUN comes up;
- ONE address per adapter ⇒ OS source selection is trivially correct — the
  mux NAT, SkipAsSource reconcile, and Linux src hints never engage (their
  `meshharbor status` evidence counters stay zero, which is exactly the
  Phase-3 deletion gate);
- each adapter's derived-ULA on-link is NARROWED to its block
  (`/(96 + v4_plen)`, a `/22` org → `/118`; the primary's is narrowed too —
  its whole `/96` would cover every sibling's embedded range), so v6
  longest-prefix picks the right adapter;
- the boot stray-adapter sweep structurally EXEMPTS `meshharbor-*` (orgs come
  up at their own pace; a sibling's persisted adapter is not a stray);
  explicit org removal owns real adapter deletion — a loop end only drops
  the process's device handle, so an EDR-watched host never sees device
  churn on reconnects;
- ICE never gathers on `meshharbor-*` (the peer.rs interface deny-list), and
  the LAN gather's `meshharbor` prefix filter already covers them.

The kill switch it shipped with (`overlay_tun_per_org = false`, back to the
shared-TUN mux of §4.4 and §4b) went with the mux in W7c.
`overlay_shared_carrier` (§4a) still composes independently and is still on by
default.

---

## 4b. Cross-org egress source normalization — the mux NAT (rc.328) — deleted in W7c

> 🗄️ **History.** This NAT compensated for two orgs' addresses on ONE shared
> adapter. With one adapter per org there is one address per adapter, and the
> OS picks the source correctly by itself, so W7c deleted it with the mux
> (§4.4). Kept for the field record below.

With two org addresses on the ONE shared adapter (§2), the **OS** picks the
source address for locally-originated traffic — and with nested blocks (a
legacy `/10` beside a carved `/22`) it can pick the WRONG org's address.
Field 2026-08-09 (winhost-a): Windows deterministically sourced grox-bound
packets from the jovanov address; Linux fleet nodes did the equivalent
(`inet_select_addr` is address-order-dependent). The packet rides the correct
pair (demux is dst-based), but a **single-org receiver** RPF-flags the foreign
source (`rx_denied_noroute` in `peers --json`), replies to an address it
cannot route, and the reply blackholes into its own on-link block route —
100 % loss on everything the multi-org host initiates toward single-org
peers, while dual-org receivers work by reply-hairpin accident and IPv6 is
immune (one overlay v6 per host).

Two-layer fix:

- **Prevention (Linux):** every route the mux installs carries
  `src <org-self>` (RTA_PREFSRC), so the kernel can't mis-pick
  (`TunIo::add_peer_route_from` / `add_cidr_route_from`).
- **Normalization (all platforms, the load-bearer on Windows, which has no
  per-route source hint):** the mux rewrites a host-originated v4 packet
  whose source is ANOTHER org's own address to the destination org's address
  (checksums fixed incrementally), records the flow, and restores the
  destination on matching replies so the OS delivers them to the socket
  still anchored to the original address (`overlay/mux_nat.rs` +
  `tun_mux.rs` hooks). Kill switch: `overlay_mux_nat`
  (`MESHHARBORD_OVERLAY_MUX_NAT`), default **on**.

Accepted limitations (all narrow): no port translation — sockets on BOTH org
addresses colliding on an identical (proto, local port, remote, remote port)
4-tuple are indistinguishable on the wire; inbound ICMP errors quoting a
normalized flow are not un-NATed (moot at the uniform 1280 MTU); a
FRAGMENTED reply to a normalized flow is delivered to the wire address and
misses the anchored socket (ingress never rewrites fragments — a
half-rewritten train fails reassembly). TCP/UDP flows that cannot be
recorded (flow table full) pass through UNrewritten with a throttled WARN —
that keeps the pre-fix behavior plus the receiver-side breadcrumb, instead
of a silently-broken rewritten flow.

## 5. P3 — remote-control concurrency (shipped, #320 + #323)

Security first (#320): `Hub::dispatch` gained **session-party checks**.
`Terminate` / `forward_ice` / `forward_offer` previously matched on session_id
with a wildcard identity — any authenticated user who learned a session id
could kill it or inject SDP/ICE. The cross-pod terminate is authz'd and no
longer a silent pod-local no-op that returned `{"terminated": true}`.

Then capacity (#323): `rc_max_sessions` (1–8, default 2;
`MESHHARBORD_RC_MAX_SESSIONS`) plus the five latent single-session
assumptions that made >1 unsafe — clipboard's single watcher slot, display-match
restore firing on any session close, per-tx controller unregistration, the
viewer's one-handler-per-type registry, and ungated INPUT/FILES data channels.
Until P6 the server kept **one INPUT holder** per agent; a second session was
created view-effective.

## 6. P5 — shared-floor encoder (shipped rc.303, #325)

Same-profile DC viewers share ONE capture + encoder. Rates merge **pre-encode**
into a floor (keyframe union, MAX frame-skip divisor, min dials): tee-side
dropping of delta frames would break reference chains, because the 13-byte DC
header carries no sequence number. A joiner buffers until the next IDR; a
viewer that sustainedly needs far less than the shared rate spills to its own
encoder, bounded at 2 pipelines total. The viewer badge shows `· shared ×N`.

## 7. P6 — InputArbiter (shipped rc.305/306, #329 + #334)

One process-global injection worker with per-session held state.

- **`free`** (default): all sessions inject; modifiers are **fenced** per
  session — the other sessions' held modifiers (HID `0xe0..=0xe7`) are
  neutralised around each burst, so one user holding Shift can't capitalise
  another user's typing. Cursor tug-of-war is accepted (TeamViewer does the
  same).
- **`exclusive`**: a single INPUT holder with request/grant over
  `rc:control.state`, and a 2 s idle takeover.
- Release-all on teardown, per-event actor audit, and `cursor:peer` ghost
  cursors so each session sees where the others are pointing. A held button is
  released **where the pointer is** (`InputMsg::MouseRelease`, #1945), never
  by a positioned button-up: that one moves first, and at the (0,0) it used to
  carry it opened GNOME's Activities hot corner.

`AgentCaps.input` gates the server's P3 single-INPUT-holder strip: the strip is
lifted only for arbiter-capable agents, so a mixed-version fleet can never end
up in chord chaos.

Two field bugs found and fixed in #334: the arbiter and the shared pipeline
broadcast their state during peer setup, **before** any control channel
existed (followers saw neither the participants chip nor the badge, and could
not request the floor in exclusive mode) — both now fire on control-DC open;
and deregistration moved to `Drop for AgentPeer`, the one point every teardown
path funnels through, which also fixed a display mode that could be left
un-restored.

## 8. P4 — cross-org realtime notifications (shipped, #324)

- **`device:presence`** WS events (online / stale / offline) carrying
  `tenant_id`. Emitted at hub register, at tx-gated unregister, and by a
  **cluster-singleton staleness sweeper** — stale and crash transitions have no
  socket-teardown moment to hook, so without the sweep a killed agent's badge
  would freeze forever. Exactly-once cross-pod emission comes from a Mongo CAS
  on a broadcast ledger; fan-out is coalesced per tenant.
- `tenant_id` added to `notification:new` and `message:create` too — without
  it client-side per-org routing is impossible.
- Consent requests now create an in-app notification row (the enum variant
  existed and was never used), and `notification:unread_count` is emitted on
  read mutations (the client handler existed with no server emitter).
- `GET /api/user/unread-summary` — per-org mentions / unread rooms / device
  alerts, refetched on `ws:reconnected` (replay-free recovery, matching the
  established doctrine).
- The UI routes non-active-org events into a per-org badge store instead of
  dropping them, and the org switcher shows per-org badges.

**Same-tab caveat:** switching orgs redials the shared WS and kills that tab's
RC session. Cross-org remote control means separate tabs.

---

## 8b. Consent names the asking org (#356)

A device in N orgs runs N signalling loops into one host, so "**Alice** is
requesting to control this device" is only half the decision: the same person
can be a colleague in one org and an outside contractor in another.

`ServerMsg::Request` carries `tenant_name`, resolved in
`resolve_session_authz` from the agent row it already loads (one extra tenant
read, only on a real session request) and threaded through `SessionAuthz` →
`DispatchCtx` → `create_session` — the path `consent_mode` and `input_mode`
already take. The cross-pod `rc.cmd` relay forwards it too, so a
foreign-homed device isn't left with an unlabelled prompt.

The agent falls back to its own org **label** when the server sends nothing
(older server), and to nothing at all on the primary enrollment — so a
single-org device looks exactly as it always did. `localapi::ConsentRequest`
carries `org`, and the tray modal renders an "On behalf of …" row, hidden
when the field is empty (an empty value is omitted from the JSON entirely, so
no blank row can render).

---

## 9. Failure modes

| Failure | Behaviour | Where |
|---|---|---|
| One org's server is down / its token is revoked | Only that supervisor backs off and retries; other orgs are untouched, each with its own `DOWN_SINCE` | P1 |
| Pod roll | Every org's WS reconnects independently and re-lands on the current LB hash; rc/tunnel/media/derp rehome per the S6 cluster layer | P1 + S6 |
| Half-open WS (middlebox ACKs pings after the upstream leg dies) | Per-connection receive-liveness deadline (rc.293): no inbound frames for 80–90 s ⇒ reconnect | pre-existing, per-org since P1 |
| Redis down | Presence sweeper aborts rather than mass-emitting from a partial view; per-pod fan-out degrades to pod-local; the UI's slow poll is the belt | P4 |
| Agent crash mid-renumber | Node rows are written before the network row, so the worst case is nodes already on new addresses with the network still describing the old range — re-running the renumber is idempotent from there | P2b |
| Renumber loses the block-allocation race | The old block is already quarantined and the network keeps its old CIDR — safe, and the retry allocates above | P2b |
| A device misses a renumber (offline) | It rejoins with a stale `self_ip`; peers already hold its new `/32`, so it is unreachable until it reconnects. Its old range is quarantined, so nothing else can claim it | P2b |
| An agent below the version floor is force-migrated | Its boot reconciler purges its own on-link route ⇒ that host's mesh blackholes until it updates | P2b |
| Two viewers, one host, mixed versions | An agent without `AgentCaps.input` keeps the P3 single-INPUT strip; only arbiter-capable agents go free-for-all | P6 |
| Encoder spill oscillation | Hysteresis on the deviation gate, hard cap of 2 pipelines | P5 |
| OS picks the wrong org's source address on the shared adapter | Mux NAT normalizes egress + restores replies (§4b); receivers count the foreign source as `rx_denied_noroute` | §4b |

## 10. Scale notes

- **Presence storms.** A pod roll reconnects a whole fleet within seconds.
  Fan-out is coalesced per tenant (`rc.presence_batch_ms`, default 2 s) and
  recipients are resolved once per tenant from a cached role→member set, so a
  200-device fleet produces one WS event per tenant, not 200.
- **Block space.** `/22` blocks give 4032 tenants × 1022 devices. A tenant that
  outgrows its block renumbers into a wider one (`prefix: 20` → 4094, `16` →
  65 534); the old block is quarantined, so growth costs address space rather
  than risking a collision.
- **Sessions per host.** `rc_max_sessions` defaults to 2. P5 makes additional
  same-profile viewers nearly free (one capture + one encoder); different
  profiles still cost a pipeline each, bounded at 2.

## 11. Test map

| Area | Tests |
|---|---|
| Config v2 + enrollment dispatch | `agents/meshharbord/src/config.rs`, `enrollment.rs` units; the two-tenant integration test driving ONE agent lib into TWO TestApps |
| Block grid + allocator | `crates/remote_control/src/models.rs` units (grid rendering, prefix→width, buddy-alignment property, in-block leases) |
| Renumber planner + version floor | `crates/api/src/routes/overlay_block.rs` units (preservation, compaction ordering, determinism, capacity refusal, numeric rc compare, fail-closed unknowns) |
| Renumber end-to-end | `crates/tests/src/overlay_tests.rs` — inert dry run, apply + invertibility + next lease, double renumber ⇒ quarantine trail, cross-tenant disjointness over mixed widths, floor refusal + force, permission gate, carve-new-networks-only |
| IPAM ceiling (P2a) | `allocate_host_stops_at_the_block_ceiling` |
| Presence | sweeper claim/dedupe + payload `tenant_id` contract locks |
| InputArbiter | pure state-machine units incl. `close_leaves_no_residue_for_the_next_session` |
| Shared encoder | floor-merge, joiner-on-IDR, spill hysteresis |

## 12. Open items

- **The refusal path runs against a real kernel; the two-control-plane
  field run is now unblocked but not yet done.** `TunMux`'s bookkeeping was
  always unit-tested against a fake device; the half that touches the OS —
  a REFUSED registration leaving no address behind, a disjoint block really
  getting one, a released org really losing it — now runs on every CI push
  (`tun_kernel_tests`, root + `MESHHARBOR_TUN_KERNEL_TEST=1`, skipped
  everywhere else). It earned its keep on its first run by catching
  `deregister` handing back the block BASE instead of the org's address.
  What is still untested is the same path driven by two real control
  planes. That needed a third organization on the legacy `/10` and a way to
  retire it afterwards; **archiving now exists** (§13), so the remaining
  work is scheduling it on a disposable host — deliberately not a prod
  cluster node, since the test is an intentional address collision.
- **macOS meshes, including multi-org — CLOSED.** `add_peer_route`,
  `add_cidr_route`, `del_*`, `purge_one` and the derived-v6 assign were
  `#[cfg(not(any(linux, windows)))]` no-ops and `add_address_sync` refused
  outright, so macOS had no per-peer `/32`s, no subnet routes and no second
  address — the overlay leaned entirely on the device's connected route.
  The mechanical cause was the interface name: `IF_NAME` was defined only
  for Windows and Linux, and utun numbers are kernel-assigned anyway
  (`utun3`, `utun7`, …), so any `ifconfig`/`route` call there would have
  addressed an interface that does not exist. `SystemTun` now captures what
  the OS actually named the device and every macOS arm uses it, with BSD
  forms throughout (`ifconfig <utun> inet A A netmask M alias` for the
  point-to-point interface; delete-then-add for routes, since BSD `route
  add` has no idempotent form).
  `enumerate_if_routes` stays empty on macOS, for the right reason: the
  boot reconciler exists for a PERSISTED device, and a utun dies with the
  fd that created it, taking its routes along — there are no orphans to
  clean.
  This stayed undone because writing OS networking you cannot run is worse
  than a loud refusal. It is run now: a `macos-latest` CI step creates a
  real utun and asserts against `ifconfig` / `netstat -rn` that a second
  address lands, a peer `/32` lands, a subnet route lands, and each comes
  back off — plus that the utun name really is kernel-assigned, so the
  hardcoded name cannot quietly return. Two orgs on one Mac were run on the
  released 0.4.143 (FR-97 P1d, macOS 15): the primary's runtime came up on
  one utun and the secondary's on the next, the anchor of the secondary's
  org routed through the secondary's utun and answered 5 of 5 pings, its
  MagicDNS bound to that utun, and a clean stop took both utuns and their
  routes away. (If a persistent macOS mesh member
  is ever wanted, a rented Apple-silicon Mac mini is ~€0.11–0.22/h with a
  24 h minimum lease — Apple licensing, which AWS EC2 Mac carries too.)
- **Netstack is per-org.** ~~One handle channel, one SOCKS port, one ping
  backend, none org-scoped~~ — each org now has its own stack and its own
  front, so two orgs in netstack mode both get a mesh. What genuinely
  cannot be shared is the PORT (one TCP listener): it keeps an owner, and a
  second org configured onto the same one withholds with an actionable
  message. The primary reads `MESHHARBORD_OVERLAY_NETSTACK_SOCKS`; a
  secondary sets `netstack_socks_port` on its `[[orgs]]` entry and
  deliberately does not inherit the env key.
  ⚠️ **Until #2493 the secondary half of this was dead code.**
  `AgentConfig::for_org` switched every non-`tun` secondary's overlay off, so
  a netstack secondary joined nothing while every surface said `overlay
  netstack`. FR-49 had made netstack the default for `enroll --overlay`, which
  made this the common case, and #2493 measured it on 0.4.143: no listener on
  the port, no peers, no log line. Now `for_org` turns a netstack secondary on
  when it has its own port and key (`crates/agent-core/src/config.rs:2114-2109`),
  and `derived_netstack` sends it to its stack rather than to the per-org TUN
  that the device-wide `overlay_multi_org` would pick
  (`agents/meshharbord/src/overlay.rs:311`). A port that is unset is **picked**:
  - at `enroll --overlay`, `org overlay <org> netstack` and a pushed join;
  - at daemon start, for an entry from before the fix.

  The pick is the first free loopback port in 10800–10899, below every OS's
  ephemeral range, that no other enrollment claims
  (`agents/meshharbord/src/org_join.rs`, `pick_netstack_port`). Free means
  nothing answers there and it binds: Windows and macOS let a loopback bind
  shadow another program's listener on the wildcard address, which only the
  connect sees. The CLI prints where the front is.
- **Block reclaim** — `POST /api/admin/overlay-block/reclaim`, platform
  operator, dry-run by default. Quarantine stays permanent by default for
  the original reason (a device that missed a renumber may still believe it
  holds an address in the old range), and reclaiming requires both a
  minimum quarantine age and no live node anywhere inside the range. The
  shape that makes this safe: **a reclaimed range is the allocator's
  exhaustion fallback, not its default** — normal allocation stays strictly
  monotonic-upward, so the risk is paid only when the alternative is no
  address at all. `GET …/overlay-block` reports
  `headroom { total, used, burned, reclaimed }`.

## 13. Archiving an organization

`Tenant.is_archived` existed from the first migration and nothing read it,
so "retire an org" had no meaning and there is no tenant-delete route at
all. It means this now: **an archived organization stops acting and keeps
everything it knows.**

`POST /api/tenant/{id}/archive` — **owner only**. Five effects:

1. hidden from the org switcher (`GET /api/tenant`; `?include_archived=true`
   still lists it — this is not erasure);
2. no new device enrollments;
3. no new remote-control sessions;
4. its devices leave its mesh — every enrollment revoked, every overlay
   node released back to the address pool, its block quarantined;
5. everything else — rooms, messages, files, members, roles, audit —
   retained untouched.

`POST /api/tenant/{id}/unarchive` restores 1–3. It deliberately does NOT
resurrect the revoked enrollments or the quarantined block: a device that
never saw the archive may still believe it holds an address in that range,
and re-issuing it is how two tenants end up sharing addresses. Devices
re-enroll; the org carves a fresh block.

Owner-only because effect 4 revokes every device's enrollment — not a
MANAGE_TENANT delegate's surprise. Archiving twice is a 400 rather than a
silent no-op that would report `devices_revoked: 0` and read like success.

Not a delete, and the reason matters: an org's data is entangled with
people who belong to other orgs, and erasure has no undo. If true erasure
is ever needed it belongs in a separate, explicitly destructive job layered
on top of this one — archive first, purge later.
