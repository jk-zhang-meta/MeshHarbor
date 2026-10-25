# Business isolation — mainland and non-mainland never meet (MeshHarbor #21)

The rule: a mainland node discovers and connects only to mainland nodes, and a
non-mainland node only to non-mainland nodes. No ACL, share, relay grant, NAT trick or
server hop overrides it, and a node whose zone is unknown, untrusted or expired is
treated as being in neither zone. Management traffic (`www.itachi.fans`) is not
business traffic and never passes through this gate.

## Where a node's zone comes from

The zone is the one observed on the node's **live connection** when that connection
opened. It is the same evidence the `auto` relay mode already uses (see
[peer-relays.md](peer-relays.md#auto--a-central-server-role-inside-one-business-zone-meshharbor)):
the trusted-proxy chain gives the client address, and the GeoIP dataset (inside its
120-day freshness rule) gives the country. `org_relay::node_zone` reads it through the
per-connection binding, for agents (bound at `hello`) and tunnel clients (bound when
the tunnel connection is created, unbound at teardown). A connection cannot change its
source address, so the zone holds for its life. A reconnect re-joins, and that join
reshapes everything below.

No trusted proxy chain, no GeoIP database, a stale dataset, or no live connection on
this pod all mean **no zone**, and no zone matches nothing, not even another node
with no zone.

## The setting

`app.business_isolation` (`ROOMLER__APP__BUSINESS_ISOLATION`):

| value | effect |
|---|---|
| `off` | the rule is not consulted; no zone lookups are made |
| `warn` (default) | every gate below computes its verdict and **logs** what it would refuse, but refuses nothing |
| `enforce` | every gate refuses |

Any other value reads as `enforce`, so a mistyped value cannot quietly switch off a
security setting. The default is `warn` because a server without zone evidence (no
GeoIP database, no trusted proxy configured) would otherwise cut every business mesh
the moment it is deployed. Switch to `enforce` once the `[warn]` lines show only the
refusals you expect.

## The gates

| carrier | gate | under `enforce` |
|---|---|---|
| netmap (full and every delta) and the device's own listing | `overlay::shape_peer`, checked before the ACL | the peer is withheld; a delta sends it as `removes`, which tears down an installed carrier |
| org relay mint, discovery, fallback, backbone | `org_relay::plan_mint_candidates_reusing` | the pair must share a zone (`zone_denied`, audited), and each candidate relay must be in that zone, explicit grants included |
| TURN grant and forced-DERP escalation | `overlay::handle_overlay_relay_request`, after the org offer | no grant is sent |
| `/derp` forwarding | `derp_acl` table: each node's zone beside the ACL allow set | a frame passes only between two nodes with the same known zone, whatever the ACL mode |

The netmap is the first line: an honest client never learns a withheld peer's key or
endpoints. The other three close the paths a stale or modified client could take with
a key or node id it already holds.

A joiner under `enforce` waits up to `JOIN_ZONE_WAIT` (2 s) for its own observation to
land before its netmap is shaped; otherwise a joiner whose evidence arrived a moment
late would be shown nobody until its next rejoin.

## Known limits

- **The DERP restart window.** The `/derp` table is rebuilt on every join and policy
  change. After a server restart, a network has no table until its first join, and a
  missing table permits frames (the ACL's fail-open posture). Every node re-joins on
  reconnect, so the window is short, and the netmap has already withheld the cross-zone
  key from honest clients.
- **Regional PoP DERP relays** (`derp-relay`) forward by ticket and see no zones. A
  pair pinned to a regional relay is gated only where the grant is issued (the TURN and
  forced-DERP gate above).
- **Direct paths** need both endpoints, which only the netmap hands out. A client that
  learned a peer's address some other way can still send to it, and the server cannot
  see that traffic. The handshake still fails: a node configures WireGuard peers only
  from its own netmap, which under `enforce` holds no cross-zone key.

## Code and tests

| piece | where |
|---|---|
| mode, `Zones`, `pair_zone`, `refuses_pair` | [`business_isolation.rs`](../crates/modules/network/src/business_isolation.rs) |
| a node's zone | `node_zone` in [`org_relay.rs`](../crates/modules/network/src/org_relay.rs) |
| netmap shaping | `shape_peer`, `shape_full_netmap`, `fan_upsert_shaped` in [`overlay.rs`](../crates/modules/network/src/overlay.rs) |
| DERP table | [`derp_acl.rs`](../crates/modules/network/src/derp_acl.rs) |
| netmap TestApp tests | [`business_isolation_tests.rs`](../crates/tests/src/business_isolation_tests.rs) |
| relay and TURN TestApp tests | `isolation_*` in [`peer_relay_auto_tests.rs`](../crates/tests/src/peer_relay_auto_tests.rs) |
