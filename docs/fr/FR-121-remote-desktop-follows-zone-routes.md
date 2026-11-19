# FR-121: Remote desktop follows the zone routes

> **Status:** in progress — claimed 2026-11-19. Tracking issue: none (GitHub Issues are
> disabled on `jk-zhang-meta/MeshHarbor`); this spec and its registry row are the record.

## Goal

A remote-desktop session obeys the logical network zones exactly as the mesh does. Zones are
the LANs behind a router's ports and the zone gateways are the router: **same zone → any path,
direct first; different zones where either is gateway-only → the media rides the mesh, which
carries it gateway to gateway** over the backbone edges the administrator drew. Nothing about a
zone is hard-coded; CN / non-CN is just today's data.

Operator, 2026-11-19: "我们的逻辑分区是 general 的 … 就像一个路由器每个端口连接的一个局域网 … 改造成
gateway 就是参考路由模式"; "我需要直接把功能做实做全 不需要过渡期 直接要最终态".

## Field evidence (2026-11-19, master `b6ce14d10`)

| # | Fact | Where |
|---|---|---|
| E1 | The mesh already routes by zone: same zone may go direct, a cross-zone pair with a `router_only` side is `backbone_only` (gateway relays only, DERP/TURN denied) | `crates/modules/network/src/network_zones.rs` `pair_requires_backbone_only` |
| E2 | Relay / gateway choice is dynamic: per-device RTT probes, reachability class, summed SLA cost + load, a 20 % / 10 ms hysteresis, multi-hop over the backbone graph | `crates/modules/network/src/org_relay.rs` `select_path`, `rank_key`, `clearly_better` |
| E3 | Remote desktop is WebRTC **outside** the mesh. Only the ICE *servers* of a strict-zone device are zone-filtered (`hub.rs` `zone_local_ice`); the viewer's servers (`/api/turn/credentials`) and every controller candidate are not, so a strict-zone host (the headless arm64 field host) can pair directly with a controller in another zone | `crates/modules/fleet/src/hub.rs` `forward_ice`, `crates/modules/remote/src/routes.rs` `turn_credentials` |
| E4 | `app.rc_ice_zone_mode` is unset in production (`warn`): the #21 business gate logs only | live compose |
| E5 | Every zone gateway runs the userspace netstack (no TUN), so a TURN relay socket bound to the overlay IP (today's loopback-TURN, `transport/turn_host.rs`) cannot exist on them | `mh status` on the four gateways |

## Design

```mermaid
flowchart LR
    subgraph ZA["zone A (controller)"]
      B[viewer] -- loopback --> TA["controller's own<br/>loopback TURN"]
    end
    subgraph ZB["zone B (host)"]
      TB["host's own<br/>loopback TURN"] -- loopback --> H[host agent ICE]
    end
    TA -- "relay socket inside the mesh<br/>(netstack or TUN overlay IP)" --> M((mesh))
    M -- "same zone: direct / in-zone relay<br/>cross zone: gateway → backbone → gateway" --> TB
```

1. **Route decision, server side (P3).** For every session the hub knows the host's zone and
   learns the controller's: the controller node (its local agent's descriptor names an overlay
   address of the same tenant) or, for a browser on no mesh node, the zone its public
   candidates' addresses belong to (a device's own public address → that device's zone, else
   GeoIP country → `auto_countries`, else the default zone — the same resolution devices get).
   `needs_mesh = pair_requires_backbone_only(controller zone, host zone)`.
2. **Mesh-routed session (`needs_mesh`).** Both sides take only `typ relay` candidates whose
   address is an overlay address of the session's two nodes; the hub drops every other
   candidate in both directions and tells the host `zone_route = mesh`; the host gathers relay
   only (`RTCIceTransportPolicy::Relay`) through ITS OWN loopback TURN. Media then travels
   relay socket → mesh → relay socket, so the mesh's own path choice (E1, E2) carries it: in-zone
   direct or relay, cross-zone gateway to gateway. A controller on no mesh node cannot be placed
   on a mesh route; its public candidates are placed one by one (`direct`), a cross-zone session
   then does not connect, and the viewer says why in one sentence.
3. **Same-zone session.** Unchanged P2P, plus: a controller's public candidate whose address
   belongs to another zone is dropped (defence in depth for a strict host), the viewer's ICE
   servers are the host zone's, and the mesh relay path is offered as a fallback candidate.
4. **Loopback TURN inside the mesh (P1).** `LocalTurnHost` gets a relay generator backed by the
   netstack's `NsUdpSocket` (send/recv any overlay address), so every node — TUN or netstack —
   hosts it; peers a relay may reach are limited to overlay addresses.
5. **Viewer (P4).** The viewer always probes its local agent (cached for a minute) but never
   holds the request for it; a descriptor found late rides `rc:sdp.offer`, where the hub settles
   the route and passes it to the device. On a zoned route the viewer adds its local relay; the
   hub passes on only the candidates the route allows, so no relay-only policy is needed in the
   browser.

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P0 | Evidence E1–E5; this spec | — | ✅ 2026-11-19 |
| P1 | Netstack relay generator for the loopback TURN; hosted on every node | `MESHHARBORD_LOCAL_TURN=0` | ✅ on master (unit: `a_netstack_turn_relays_into_the_mesh`, mutation-checked); field pending |
| P2 | Host side: `zone_route` (`direct` / `direct_mesh` / `mesh`) on `rc:request`, superseded by `rc:sdp.offer`; relay-only through its own loopback TURN on `mesh`; the address filter on every zoned route | an older server never sends `zone_route` | ✅ on master; field pending |
| P3 | Hub: per-session zone route by the mesh's pair rule, settled at the offer; candidate filtering both ways (trickle, SDP, file children); viewer ICE servers | a tenant without zones is `Open` | ✅ on master; field pending |
| P4 | Viewer: probe always (cached, never before the request), descriptor on the offer when late, local relay added on zoned routes, one sentence when a zoned session from no mesh node fails | — | ✅ on master; field pending |
| P5 | Docs: `docs/remote-control.md` §4.5 (mermaid, table), `docs/README.md` row | — | ✅ |

## Acceptance criteria

- [ ] A controller in zone A and a host in zone B (either gateway-only) connect, and the host's ICE shows only a relay pair on overlay addresses; the mesh carries it over the A↔B gateway edge.
- [ ] The headless arm64 host (strict CN zone) never sends a packet to a non-CN address during a session from a non-CN controller (capture on the host).
- [ ] Same-zone sessions keep their direct pair (p50 unchanged within 10 %).
- [ ] A browser on no mesh node, cross-zone to a gateway-only host, gets the one-sentence refusal, no hang.
- [ ] Works with both ends on the userspace netstack (no TUN).
- [x] `docs/remote-control.md` describes the zone routes with a mermaid diagram, and `docs/README.md` indexes it.

## Out of scope

- Public TURN on gateways for browsers on no mesh node (the refusal stands until an operator asks).
- Changing how gateways are chosen; the mesh's selection (E2) is used as is.

## Field-verification log

| Date | Version | Result |
|---|---|---|
| 2026-11-19 | branch, before release | integration: 104 remote-control / share / zone tests pass; 4 `business_isolation_tests` (`staged_*zone*`) fail identically on master `047208482` (baseline, pre-existing) |
| 2026-11-19 | server + UI `52b458b0d` (before) | FAILED, same zone (CN controller → strict-CN arm64 host): the session's ICE list, after the strict zone dropped every non-CN STUN, held only the one TURN-over-TLS server, and its port is unreachable from the mainland. Neither end learned a public address: the browser offered one mDNS name the host could not resolve, and no candidate pair formed. The zone-tagged in-zone STUN servers in `turn.stun_urls` had only ever been handed to the mesh |
| 2026-11-19 | server + UI `52b458b0d` (after) | PASSED, same zone, headless browser on a CN mesh node: the session's ICE list now leads with the device zone's own STUN servers (`with_zone_stun`); the browser gathered a server-reflexive candidate, ICE reached `connected` on a **direct** pair, first frame 1.8 s, the bundled Xfce desktop on screen. Two viewer-side gaps found on the way: Chrome's Local Network Access gates the loopback probe (the viewer now reads the permission and waits for the prompt instead of timing out), and the agent's origin allowlist named a retired domain (fixed in agent 0.4.178: the daemon allows its enrolled servers' origins) |
| 2026-11-19 | agent 0.4.178 (`fa9408ef8`), rolled to all 20 online nodes | the daemon's loopback descriptor answers the production origin with `Access-Control-Allow-Origin` and a foreign origin without one (both probe ports, a mesh node) |
