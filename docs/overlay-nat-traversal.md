# Overlay NAT-traversal cascade

> Cross-ref: the L3 overlay mesh is part of the remote-control / tunnel
> subsystem ([`docs/remote-control.md`](./remote-control.md)). This doc covers
> how two overlay nodes pick a WireGuard **carrier** — and, in particular, how
> a NAT'd node reaches another without a relay hop. The Windows-firewall piece
> is [`docs/overlay-wfp.md`](./overlay-wfp.md); the exit-node routing on top of
> a carrier is [`docs/overlay-exit-nodes.md`](./overlay-exit-nodes.md).
>
> For the **end-to-end picture with diagrams** — control plane vs data plane,
> every tier as a sequence diagram, and which one wins inside vs outside a
> corporate VPN — see
> [`docs/overlay-communication.md`](./overlay-communication.md).

## The carrier cascade

Every overlay peer link rides one **carrier** — the transport the WireGuard
datagrams travel over. The runtime picks the best one available, in priority
order, and demotes to the next tier if it can't establish:

| Tier | Carrier | When it wins | Flag (default) |
|---|---|---|---|
| LAN direct | UDP on the shared interface socket | peer shares one of our /24s | `ROOMLERD_OVERLAY_DIRECT` (**on**) |
| **A** direct-to-public | UDP via an unbound egress socket | peer's NIC holds a public IP | `ROOMLERD_OVERLAY_PUBLIC_DIRECT` (**off**) |
| **C** srflx hole-punch | UDP via the **punch socket** | both ends NAT'd (not both symmetric) | `ROOMLERD_OVERLAY_SRFLX` (**on** since rc.200) |
| **D** single-relay | ONE coturn allocation + a raw dialer, QUIC-over-TURN | nothing direct works **and ≥1 side is UDP-capable** | `ROOMLERD_OVERLAY_RELAY_SINGLE` (**on** since rc.200) |
| **D″** DERP | `/derp` WSS on `roomler.ai:443`, pubkey-addressed, raw WG | **both** ends UDP-blocked (TCP-only net) | `ROOMLERD_OVERLAY_DERP` (**on** since rc.203) |
| **D‴** org relay | a tenant-owned `roomlerd` forwarding Geneve-framed WG ciphertext on UDP 3478 (FR-19) | the server **minted a session** for the pair (org switch, ACL grant per member, an approved + serving relay) — a relay *kind* beside TURN/DERP, not a new tier | `ROOMLERD_OVERLAY_ORG_RELAY` (**off**) |
| **D′** both-allocate relay | two coturn allocations (raw / QUIC) | single-relay off, or a mixed-capability pair | always available (fall-through) |

LAN direct and the relay predate this work (rc.131–rc.135; the relay is the
original path). **Phases A / C / D** are the NAT-traversal cascade. **C (srflx
punch) and D (single-relay) shipped default-ON in agent rc.200** after being
field-proven in a buildhost↔fleet-host-2 netns NAT lab (cone↔cone → direct punch 0% loss
~0.6 ms; sym↔sym → single-relay 0% loss ~1.3 ms). A is still default-OFF
(public-on-NIC is rare and its own field arc). Each gate takes
`0`/`false`/`no`/`off` to disable. Single-relay needs the QUIC carrier
(`ReadyLink.single_relay` forces it): a raw relay carrier discards the recv
source, so an anchor can't reply to a symmetric dialer's coturn-observed port —
only quinn's server consumes it.

The relay always works but is the worst option: it adds a hop's latency, a
coturn dependency (dies on UDP-blocked / TLS-inspecting corp nets), and — for
the exit-node feature — a cross-NAT **hairpin** that never carried in the field.
Getting off the relay is the whole point.

```mermaid
flowchart TB
    START["peer appears in netmap"] --> LAN{"shares one of<br/>our /24s?"}
    LAN -->|yes| LOK["LAN direct<br/>(interface socket)"]
    LAN -->|no| PUB{"peer NIC holds<br/>a public IP?<br/>(flag: off)"}
    PUB -->|yes| POK["direct-to-public<br/>(unbound egress socket)"]
    PUB -->|no| SRFLX{"both NAT'd,<br/>not both symmetric?"}
    SRFLX -->|yes| CPUNCH["srflx hole-punch<br/>(the punch socket)"]
    SRFLX -->|"both symmetric"| REL{"≥1 side<br/>UDP-capable?"}
    CPUNCH -->|"punch fails"| REL
    REL -->|yes| SINGLE["single-relay:<br/>ONE coturn allocation,<br/>QUIC-over-TURN"]
    REL -->|"both UDP-blocked"| DERP["DERP: /derp WSS :443,<br/>pubkey-addressed raw WG"]
    SINGLE -.->|fallback| BOTH["both-allocate relay"]
    LOK & POK & CPUNCH -->|"established"| MBB["stay; upgrade probes may<br/>promote a better tier later<br/>(make-before-break)"]
```

## What each direct tier needs

- **LAN direct** — the peer advertised an `ip:port` sharing one of our /24s.
  Reliable L2, no NAT games. One socket per interface (bound to the interface
  IP + `IP_UNICAST_IF`-pinned on Windows) so a full-tunnel VPN can't steal the
  egress.
- **Phase A (direct-to-public)** — the peer's NIC holds a **public** IP (bare
  metal / Hetzner, not 1:1-NAT). A NAT'd client dials it directly; WireGuard
  endpoint-roaming + the exit-side *accept* path (below) complete the handshake.
  No STUN needed — the public side has no NAT filter to open.
- **Phase C (srflx hole-punch)** — **both** ends are NAT'd. Each learns its own
  public mapping via STUN (server-reflexive = "srflx"), advertises it, and the
  two dial each other simultaneously so both NATs' filters open. This is the
  classic UDP hole-punch, described in detail below.
- **Phase D (relay)** — last resort; see "Relay" below.

### When the LAN tier is gated: a VPN capture, or a dead own route

FR-33 gates the LAN tier off when a packet to a LAN neighbour would leave
through another interface. That is a corporate VPN's split-prefix capture
(`crates/tunnel-core/src/overlay/path.rs:900`). Routing around a capture is
VPN policy evasion, so the gate only reports it. The fix belongs in the VPN
profile.

The same lookup also fires when the interface's **own** prefix route is broken
underneath it. On CORPLAP-3 (2026-10-10), AnyConnect in split-exclude listed
the home LAN `192.168.8.0/24` as non-secured, yet the Wi-Fi's own on-link row
carried next hop `192.168.0.1`, a gateway from a network the laptop had left.
ARP left it `Incomplete`. Windows skipped the row, a LAN packet fell through to
the VPN's `0.0.0.0/0`, FR-33 read "captured", and the pair relayed. An on-link
ping answered in 1 ms. AnyConnect's own "Routing table - Original" snapshot
already held the stale row, so a VPN reconnect does not cure it.

That case is repaired, not reported
(`crates/tunnel-core/src/overlay/lan_repair.rs:165`, run from the network-state
sample before the capture probe at `netstate.rs:537`):

```mermaid
flowchart TD
    A["LAN address on interface I, prefix P"] --> B{"I's own row for P:<br/>next hop set and outside P?"}
    B -- "no (on-link, or missing)" --> N["nothing to repair<br/>(FR-33 reports any capture)"]
    B -- "yes: dead row" --> C{"another interface routes P<br/>or anything inside it?"}
    C -- yes --> X["a capture: stand aside<br/>(remove our halves)"]
    C -- no --> D{"the dead next hop belongs to another interface?<br/>(its row's next hop, or inside its subnet)"}
    D -- yes --> X
    D -- no --> R["install P on-link as two halves (plen+1)<br/>on I, metric 0; the dead row is left as it is"]
```

| Check | Why |
|---|---|
| Next hop outside the prefix | A next hop has to be on-link, so this row can never carry a packet. |
| No other interface routes the prefix (`lan_repair.rs:154`) | A VPN captures a LAN with rows of its own (Check Point's two `/25`s via its adapter). Then this is a capture, never ours to route around. |
| The dead next hop belongs to no other interface (`lan_repair.rs:142`) | A LAN row pointed *into* a tunnel (its gateway, its subnet) is how a VPN could block a LAN it does not exclude. A stale gateway belongs to nobody. |
| Two halves, not a replacement | They outrank the dead row by length, and nobody's row is deleted or edited. |
| Stateless | Every sample re-derives the verdict from the table. Halves are removed when the row heals, the interface moves to another network, a capture appears, or the switch is off. A restart leaves nothing orphaned. |

> ⚠️ The repair never lifts a real capture. When a capture is real, the VPN's
> filter drops the LAN traffic too (FR-33 pktmon, 2026-09-03), so nothing could
> pass anyway, and pretending otherwise would bring back FR-33's futile probes.

Switch: `ROOMLERD_OVERLAY_LAN_ROUTE_REPAIR` / config `overlay_lan_route_repair`
(Windows; default on; off removes the halves). Each install is one WARN line
naming the prefix, the interface and the dead next hop.

## Phase C: the hole-punch, precisely

Two facts about this codebase's WireGuard make the punch simpler than a generic
ICE agent:

1. **WG *is* the punch burst.** A direct carrier initiates bilaterally
   (`install_ready` / `add_direct_peer` with `initiate=true`), and boringtun
   retransmits the handshake INIT every ~5 s for ~90 s. So both ends are already
   firing INITs at each other on a tight cadence — no separate "punch packet".
2. **The netmap fan-out *is* the rendezvous.** When a node trickles its srflx
   (`rc:overlay.srflx`), the server fans a netmap delta to every peer within
   WS-delivery skew (~sub-second). NAT mappings/filters live ≥30 s, so the two
   ends don't need a shared clock — first attempts are naturally near-
   synchronous, and the periodic re-upgrade tick (below) closes any larger skew.

So Phase C is **not** a rendezvous protocol. In sequence form:

```mermaid
sequenceDiagram
    participant A as Node A (behind NAT-A)
    participant S as Server (netmap fan-out)
    participant B as Node B (behind NAT-B)

    A->>S: rc:overlay.srflx {ip:port seen by STUN, from the punch socket}
    B->>S: rc:overlay.srflx {…}
    S-->>A: netmap_delta: B's srflx endpoint
    S-->>B: netmap_delta: A's srflx endpoint
    par both dial from their punch socket
        A->>B: WG handshake INITs (retransmit ~5 s for ~90 s)
        B->>A: WG handshake INITs
    end
    Note over A,B: first packets open each NAT's outbound mapping —<br/>crossing INITs complete the punch (WG itself IS the punch burst)
    A-->>B: direct carrier established (srflx tier)
```

It's five concrete pieces:

### 1. Dial from the socket that owns the advertised srflx ("the punch socket")

The load-bearing rule. A srflx mapping is created by *the socket that sent the
STUN query*. If we advertise the mapping from socket **S** but then dial the
peer from a different socket **P**, our INITs from P open a *different* mapping
the peer never dials, and the peer's INITs to our S-mapping hit our NAT's filter
(S never sent toward the peer) — so **both directions fail** on anything
stricter than full-cone.

Fix: `gather_srflx` returns each candidate paired with the socket it was
gathered on; the runtime records the first as `DirectCtx.punch` and
`install_srflx_direct` dials the peer's srflx **from that socket**. Now our
outbound INIT (a) rides the mapping we advertised and (b) opens our filter
toward the peer's srflx — exactly what port-restricted-cone needs. (Phase A
keeps dialing via the arbitrary-egress `public_sock`: the public peer has no
filter, so the mismatch is harmless there.)

### 2. Keep the srflx fresh (demux-routed STUN keepalive)

A UDP NAT mapping expires on an idle node (30 s – 5 min). A gather-once srflx
goes stale for a peer that joins later. The keepalive task (`run_srflx_keepalive`,
`ROOMLERD_OVERLAY_SRFLX_KEEPALIVE_SECS`, default 20, `0` = off) re-runs a
STUN Binding on the punch socket every interval — both holding the mapping open
and detecting a change.

The punch socket's `recv_from` is owned by the overlay's demux loop, so the
keepalive can't read replies directly. The demux forwards any datagram that
carries the STUN magic cookie **and is not WireGuard-shaped** to a STUN sink the
keepalive drains. (The two wire shapes are disjoint: WG's 4-byte little-endian
type header leaves bytes 1..4 = 0, a STUN Binding message always has 0x01 in
byte 1 — so a WG data packet whose index bytes collide with the cookie is still
routed as WG.)

The STUN target is **pinned** once at startup (re-resolved only after several
failures): the fleet resolves `coturn.roomler.ai` to several workers, and an
unpinned target would make every DNS rotation look like a mapping change and fan
a network-wide re-trickle every tick. Re-trickle happens **only** when the punch
mapping actually changes; a STUN outage retains the last-known advert.

### 3. Time out a punch that never establishes

A failing punch sends no *data*, so it's invisible to the relay-fallback health
sweep (which watches the `tx`/`rx` data counters), and boringtun stops even
keepalives once the 90 s attempt expires — the carrier would zombie forever. A
lock-free `handshake_complete` flag (`PeerStats.handshake`, latched in
`process_inbound` the instant a session establishes) lets the sweep tear down a
srflx/public carrier that hasn't handshaken within its deadline (**srflx 12 s**,
**public-direct 30 s**) and fall back to relay. Once the handshake latches, the
normal data-traffic health check governs the established link.

### 4. Skip a punch that can't work (NAT-type probe)

Symmetric↔symmetric can never punch (neither can predict the other's per-
destination port). At startup each node probes its NAT mapping type — STUN the
punch socket against **two distinct targets**; same public mapping ⇒ `cone`
(punchable), different ⇒ `symmetric` — and advertises it (`OverlaySrflx.nat`,
surfaced as `NetmapPeer.srflx_nat`). A dialer skips the srflx tier **only** when
**both** ends are symmetric; any `cone`/unknown side still attempts (an unknown
stays optimistic — the tight deadline bounds a wasted try).

### 5. Retry without waiting for a netmap

A decayed failure penalty otherwise only takes effect on the next netmap; a
quiet mesh would never re-attempt direct after a fallback. A re-upgrade tick
(~every 30 s) re-runs the path-monitor decision over the current netmap,
retrying a tier whose penalty has decayed back under the eligibility bar and
driving punch convergence at large install skew.

### 6. Map the punch port on the gateway (PCP, NAT-PMP, then UPnP IGD)

A punch needs one end whose NAT accepts any remote. A gateway port mapping
gives exactly that, so a symmetric↔symmetric pair still goes direct when one
side's gateway grants a mapping. This is the step 4 case that otherwise falls
to relay. Reference: Tailscale's portmapper, which tries the same three
protocols. Mainland ISP gateways mostly speak only UPnP.

- **Who asks:** the srflx keepalive owner. That is the plane srflx task in
  plane mode (the default), or the legacy `run_srflx_keepalive`. It asks
  once at start, after the STUN advert is already out, so a gateway that never
  answers (most cloud VMs) delays nothing. The cost is at most 3 ×
  `portmap::WAIT` = 1.5 s in that task (PCP, NAT-PMP, SSDP), after which a
  host with no mapper sends no further probes.
- **What it asks:** a mapping of the punch socket's own port, with the gateway
  taken from the default route's next hop (`netstate::default_gateway_v4`).
  PCP is tried first, then NAT-PMP, then UPnP IGD (`portmap/upnp.rs`).
- **UPnP IGD:**
  - **Discovery:** an SSDP `M-SEARCH` for `InternetGatewayDevice:1` and `:2`,
    sent to the gateway's `:1900` and to the multicast group.
  - **Device description:** fetched over HTTP; the client looks for a
    `WANIPConnection:2`, `WANIPConnection:1` or `WANPPPConnection:1` control
    URL.
  - **SOAP actions:** `GetExternalIPAddress`, `AddPortMapping` and
    `DeletePortMapping`, over a minimal HTTP/1.1 client (offline builds have
    no HTTP or XML crate).
  - **Trust:** only the gateway. The SSDP reply must come from it, and the
    description and control URLs must point at it.
  - **Retries:** a permanent-only router (725) is asked again with lease 0, and
    a taken external port (718) moves to a random one.
  - **Fallback order:** UPnP is tried only on a fresh ask. A PCP or NAT-PMP
    mapping that fails to refresh counts as a loss, and the retry tries all
    three protocols again.
  - **Cost:** a silent network costs at most about 1.5 s, once, in the
    background.
- **When it is used:** only when the external IP is one STUN saw. A
  different IP means the gateway is not the NAT peers would reach (a second
  NAT); `portmap::map_udp` already refuses a private or CGNAT external address.
- **What peers see:** the external address goes FIRST among the srflx
  candidates (peers dial index 0 first) and the advertised NAT becomes
  `cone`, so the both-symmetric skip does not fire. The keepalive's own
  STUN state stays STUN-only, because `[0]` is still the punch mapping it
  compares against.
- **Lifetime:**
  - The mapping is refreshed at half its granted lifetime, and at once when
    the STUN mapping moves.
  - A lost mapping is re-advertised without the candidate and asked for again
    after 5 min.
  - The legacy task releases the mapping on a clean exit. An aborted task (a
    plane rebuild) leaves the mapping to expire.
- **Why the PCP nonce is keyed:** the nonce is HMAC(node secret, local IP,
  port), not random. The direct port is stable across restarts, and a gateway
  refuses a MAP for a port it already maps under another nonce
  (`NOT_AUTHORIZED`, for the rest of the old lifetime). With the same nonce, a
  restart or rebuild re-requesting the port is a refresh. In plane mode the
  first org runtime's key wins, like the gather.
- **Visibility:** `roomler status` shows `gateway pcp <ip:port>` on the srflx
  line, in plane mode. Legacy mode logs the grant (`gateway port mapping
  granted`) but its status keeps the startup snapshot.
- **Kill switch:** `ROOMLERD_OVERLAY_PORTMAP=0`, config key `overlay_portmap`.
- **Lab-verified against miniupnpd 2.3.9** (nftables backend), using three
  network namespaces: LAN client, router and WAN. The ignored test
  `portmap::tests::portmap_live_gateway` runs the real `PortMapper` against
  the default gateway and waits for one datagram from outside.

  | path | map time | datagram from the WAN side | after release |
  |---|---|---|---|
  | PCP | 3–4 ms | delivered via the DNAT rule | rule removed |
  | UPnP IGD (`WANIPConnection:2`), NAT-PMP/PCP off | 55 ms | delivered | `DeletePortMapping` removed it |

  - **Restarting without a release:** the same keyed nonce maps the same
    port again.
  - **A random nonce:** miniupnpd also accepts it, taking the mapping over;
    it does not check the nonce on MAP, as the IETF draft that dropped that
    check proposes.
  - **But a delete under any other nonce is refused** ("Unauthorized to
    remove PCP mapping"). So the keyed nonce is what lets a restarted node
    release its previous run's mapping. It also covers servers that do refuse
    the MAP.
  - **Not covered by the lab:** the NAT-PMP path on its own (miniupnpd
    serves PCP and NAT-PMP under one switch), which is covered by the unit
    tests, and a real ISP gateway.

### 7. IPv6 candidates: direct without NAT

Mainland home broadband and mobile mostly hand out global IPv6. Between two
such hosts there is no NAT, only a stateful firewall, and the simultaneous
dial of a punch opens that the same way it opens a NAT's filter. So a pair
whose IPv4 NATs are both symmetric, which step 4 sends to relay, can still go
direct.

- **Socket:** one `[::]:<direct port>` socket, IPV6_V6ONLY so it shares the
  port number with the IPv4 binds (`direct::bind_direct_socket_v6`). It is
  bound in the carrier plane, and in legacy `setup_direct`, only when the
  host has a global address (`2000::/3`, `direct::gather_global_v6`, with
  the same interface hygiene as the LAN gather). The plane gives it its own
  recv loop.
- **Advert:** `[addr]:port` per global address, appended AFTER the IPv4
  srflx candidates, so `[0]` stays the punch mapping both keepalives compare
  against. The server stores candidates verbatim and old clients' pickers keep
  only public IPv4, so no server change and no compatibility break.
- **Dial:** when the peer advertises a global IPv6 and we have the socket,
  the srflx tier dials IPv6 first (`direct::pick_v6_endpoint_rotated`). There
  is no NAT-type gate and no hairpin gate, because there is no NAT. After
  `direct::V6_FIRST_STRIKES` (2) failures, for example a firewall that never
  opens, the IPv4 rules take over. `DirectCtx::srflx_sock` picks the socket
  by the destination's family.
- **Accept:** an authenticated init from a global IPv6 source classifies as
  Srflx or Public, like a public IPv4 one.
- **Exit nodes:** while an exit is active, IPv6 is captured too (`::/1` +
  `8000::/1`, fail-closed). So an IPv6 carrier's destination goes into the
  exemption set like an IPv4 one and is pinned through the IPv6 uplink.
- **Kill switch:** `ROOMLERD_OVERLAY_IPV6=0`.
- **Lab-verified** (five network namespaces):
  - **Setup:** two nodes, each behind a router with a symmetric IPv4 NAT
    (`masquerade random,fully-random`) and a stateful IPv6 firewall
    (forward policy drop; `ct state established,related` and LAN-outbound
    accepted). STUN runs on two vantages and the control plane is a TCP
    splice.
  - **With IPv6:** the pair went direct 3.5 s after start, and router A's
    conntrack showed the ASSURED `2001:db8:a::2 ↔ 2001:db8:b::2` UDP flow.
    The F0 cut and heal on that path stalled 1.8 s and returned in 4.6 s.
  - **With `ROOMLERD_OVERLAY_IPV6=0`:** the pair "never settled on direct
    within 120 s" and stayed on relay.
- **Address changes** (privacy-address rotation, or a new prefix after a
  PPPoE redial): both keepalive owners re-derive the IPv6 candidates from the
  host's current addresses every tick (`refresh_v6_adverts`) and re-advertise
  on a change, with no plane rebuild, because the socket is bound to `[::]`.
  - **Lab check:** B's address moved from `::2` to `::3` mid-run; A received
    `[2001:db8:b::3]` and the pair formed a new ASSURED direct flow to it.
- **Not done:**
  - a host whose IPv4 STUN gather fails advertises no IPv6 either (the
    candidates ride the IPv4 gather);
  - legacy mode's socket wiring is unit-covered only; the lab ran plane mode.

### The accept side

Both A and C rely on the exit/peer *accepting* an inbound INIT from a source it
couldn't know in advance (a NAT'd dialer's mapping). The demux forwards an
unknown-source WG **handshake INIT** to the runtime, which **cryptographically
authenticates** it (a throwaway `Tunn` performs the full Noise-IK validation —
`parse_handshake_anon` alone proves only a *claimed* key) before installing or
re-pointing the peer onto the arriving socket + source. An authenticated INIT
that traversed both NATs is proof the pair can reach each other, so it clears
the peer's srflx penalty and strikes and books a strong inbound credit on the
path monitor — the packet's arrival is itself the measurement.

## Path selection: the two-plane PathMonitor (CC1 lives on)

Since the overlay consolidation (shadow rc.245 → consumed rc.271 → default
rc.276 → only implementation rc.282), tier selection is a measured decision by
the **PathMonitor** (`tunnel-core/src/overlay/path.rs`), a pure clock-free
module fed at every decision surface: netmap, health sweep, authenticated
inbound INIT, resume, and the ~30 s re-upgrade tick. It keeps the legacy
cascade's guarantees while replacing its reactive counters:

- **Eligibility plane — parity-exact with the legacy cooldowns.** Each tier
  carries a prior `B` (LAN 400 / public 330 / srflx 260 / relay 200). A
  failure books a decaying penalty `W = 2×(B − B_relay)` (400/260/120) with
  half-life **60 s** ordinarily and **900 s** after repeated failures
  (2 strikes for LAN/public, 3 for srflx) — reproducing the old 60 s cooldown
  and 15 min escalated deny bit-for-bit at the decision boundaries. A tier is
  probe-eligible iff `B − P ≥ B_relay`, and because penalties always decay to
  zero, **every tier retries eventually — lockout is impossible by
  construction**. Penalties are keyed per-(peer, tier), so CC1 — a routinely
  missing punch can never poison a proven LAN or public-NIC path — holds
  structurally, not by convention.
- **Ranking plane — advisory.** A quality score `Q` (EWMA, clamped ±100)
  ranks among *already-eligible* tiers: a latched probe credits by measured
  handshake latency, healthy traffic credits slowly, bad sweeps and typed
  carrier deaths debit, an authenticated inbound INIT credits strongly (the
  packet itself is proof of reachability). `Q` may reorder probing among
  eligible tiers but can never delay or advance eligibility itself — locked
  by the `no_q_state_can_delay_or_advance_eligibility` test family.
- **Availability: a gate outside both planes.** A tier is considered only if
  the peer has a dialable candidate for it (`TierAvailability`, built from the
  netmap candidates in `runtime/establish.rs`): a NATed peer has no public
  tier at all. An untried tier carries no penalty, so it always reads
  *eligible*. `roomler why` therefore shows availability as well: an
  unavailable tier reads `—` in ELIGIBLE and `no candidate` in WHY NOT
  (#2089). Before that, a NATed peer's `public yes 330` out-scored the relay
  the pair was actually on, which read as the selector ignoring its best tier.
- **Hysteresis.** Upgrades require a latched shadow-handshake probe
  (promote-on-latch); demotion happens only on a typed `DeathReason` from the
  lifecycle module; voluntary switches are ≥30 s apart per peer. The
  bilateral 60 s LAN punch cadence is pinned in the probe scheduler
  independent of any score (the hibernate-recovery cadence survives mixed
  fleets by construction), except inside a fast-return lane (F3b, below),
  where one end probing more often only adds chances to land inside the
  other end's open firewall window.
- **Active revalidation (Stage 2).** The health sweep pokes an established
  carrier with a forced WG rekey when it has been silent > 30 s, or when no
  *initiator-role* handshake has completed in 120 s (initiator-role only —
  a responder session proves the peer can reach us, not that we can reach
  them; the rx-anchored rules are structurally blind to a carrier whose tx
  is dead while the peer's own traffic keeps arriving, field 2026-08-08).
  A poke unanswered past the tier's handshake deadline dies
  `RekeyUnanswered` — detection in ~42 s for the VPN-filter class and
  bounded ~2.5 min for the one-way class, vs. the 60/90 s rx-stale backstop
  that never fires at all on the one-way shape. `RekeyUnanswered` books
  **no strike, no penalty, no Q movement**: the rebuild's own outcome is
  the evidence (a failed re-attempt books `HandshakeDeadline` ~12 s later;
  a transient recovers with zero penalty and cannot feed the forced-DERP
  churn escalation).
- **The Major fast lane (#26).** A poke armed by a netstate **MAJOR** — the
  default route moved or addresses vanished, i.e. the VPN-transition
  signature — is judged on `MAJOR_POKE_DEADLINE` (2 s) instead of the tier's
  deadline, and the next health sweep is pulled forward to just past it rather
  than waiting for the 5 s grid. The tier deadlines answer *"can a carrier
  ESTABLISH here?"* (NAT punch + allocation + both grants) and are generous by
  design; re-validating an **already-established** carrier is one round trip,
  and paying the establish-sized price for it WAS the transition hole —
  measured 2026-08-24 as 9 dropped pings on a LAN/Srflx pair and 34 on a
  public one, each matching its tier deadline almost exactly. A Major also
  **re-arms** a poke already in flight (pre-#26 it skipped those carriers, so
  a poke armed seconds earlier by the silence trigger kept the 12-30 s window),
  which is what lets the tight window judge a *fresh* initiation.
  Two bounds keep it safe: only ESTABLISHED **direct** carriers are armed, and
  the chattier addr/iface cause (a virtual adapter blinking, a lease renewal —
  up to once per 3 s, vs. one Major per 120 s) still arms its poke on the
  **tier** deadline. The residual hole is now dominated by netstate's own
  debounce (0.75 s, capped at 3 s during a signal storm), which is deliberate
  flap damping — see `MAJOR_PUBLISH_COOLDOWN`.
  ⚠️ The trade: a 2 s window judges ONE initiation where 12 s judges 2-3, so a
  single dropped handshake convicts. That is the right side of an asymmetric
  bet — a false conviction *degrades* the pair to the relay floor and
  re-upgrades (no strike is booked, so the tier stays eligible), while a late
  conviction is 100 % loss for its whole duration. The conviction log line
  carries `from_major=` so the field can measure whether it is ever too eager.
- **Demote-follow (#27) — the other end.** Fast conviction on ONE end is not
  enough, because a transition's outage is `max(both ends)`, not `min`. The end
  whose network did **not** change gets no Major, so it has no fast lane at all
  and waits out `POKE_SILENCE_AFTER` (floored by the ~25 s WG keepalive) plus
  its tier deadline. Measured 2026-08-24: the transitioning host demoted in
  2.3 s, its peer took **67 s**, and the pair was 100 % dark in BOTH directions
  for the whole gap — our frames were dropped by the peer's `DerpMux::deliver`
  (no conn for a peer it still held on direct) and the peer's replies rode the
  path we had abandoned.

  So an inbound `/derp` frame that no local conn can route is now a **signal,
  not a silent drop**: a peer only relays once it has demoted, so we follow it
  onto DERP immediately (`RelayCoordinator::follow_peer_to_derp`). This is the
  carrier-layer twin of WireGuard endpoint roaming, which already existed for
  the direct plane (`carrier_plane` `SessionRoam`) and never for DERP.
  ⚠️ A follow also **suppresses the direct tier it left** (#29). Without that,
  make-before-break re-promotes the moment its probe latches, the peer keeps
  relaying, the follow drags us back, and the pair flaps on MBB's cadence —
  field 2026-08-25, every 60 s for hours, starting the minute the follow
  shipped. A latched probe proves a path *carries*; it says nothing about
  whether the peer intends to **use** it, and the peer's own frames are the
  better evidence. `on_peer_relayed_instead` books the penalty but deliberately
  **no Q slam** — nothing died and the path may be fine.
  ⚠️ The penalty ALONE does not hold, and believing it did cost a second field
  round: `suppression_half_life` pins LAN-under-MBB to `H_ORDINARY` (60 s) by
  the P8 never-strand rule, while MBB re-probes every ~70-80 s — so the tier is
  eligible again by the next probe and the flap simply resumes. It therefore
  also opens a hard `RELAYED_INSTEAD_HOLDOFF` window during which every direct
  tier is **ineligible outright**. That is the honest shape anyway: where the
  peer *is* is a fact, not a quality score. Every follow re-arms the window, so
  it self-extends while the peer stays away and lapses once it stops relaying —
  the next probe then promotes normally and nothing is stranded.
  ⚠️ And the window **escalates** (3 → 6 → 12 min, capped at `H_ESCALATED`),
  because a FIXED holdoff only moves the flap to its own boundary: the field
  showed a pair retrying at exactly 3 min once the holdoff shipped. A gap
  longer than `RELAYED_INSTEAD_MEMORY` resets it to the base rung, so a one-off
  transition never inherits an escalated window.

  It is safe to act on because the relay **stamps** the source pubkey from the
  sender's authenticated registration — it is not sender-chosen — so the signal
  can only name a node registered in this network whose ACL permits reaching
  us; an unknown pubkey is ignored outright. Bounds: no-op when already on
  DERP, one follow per peer per `DERP_FOLLOW_COOLDOWN`, and — unlike a server
  force-DERP escalation — **no TTL pin and no `roles` override**, so the pair
  re-upgrades normally once the network settles. Both `deliver` drop classes
  now carry counters (`DerpMux::drop_counts`); they were silent, which is why
  this cost a day of field time to find.
- **A route must not outlive the conn that consumes it (#32).** The mux's
  `src_pubkey → {wg, tunnel}` table is written by the vend methods, replaced
  "last one wins", and was never cleaned — it relied entirely on a dropped
  `DerpConn` closing its channel, which is the invariant `deliver` assumes and
  nothing enforced. `DerpConn` now retires its own route on drop. ⚠️ Only its
  OWN slot and only if still its own sender (`Sender::same_channel`): a rebuild
  registers the new conn *before* the old one drops, so a blind clear would
  unregister the LIVE consumer, and the WG and tunnel routes are independent —
  a carrier going away must not take R4's tunnel route with it.
- **WireGuard is its whole header, never its first byte (#2002).** The mux splits each
  inbound payload between the WG and tunnel routes with `payload_is_wg_or_disco`
  ([`derp_frame.rs:39`](../crates/remote_control/src/derp_frame.rs#L39)), and the server's
  relay reads the same function to decide what its tunnel shaper applies to
  ([`modules/network/src/derp.rs:602`](../crates/modules/network/src/derp.rs#L602)). It
  read the first byte only, 1..=4, and quinn **greases QUIC's fixed bit** by default
  (RFC 9287): an end whose peer advertised the parameter clears the bit on about half of
  what it sends, so a tunnel short header can open on any byte below 0x40. Measured over a
  2 MiB echo between the two DERP endpoints: 1,881 of 3,761 datagrams greased, **151
  (4.0 %) opening on a WireGuard type byte** (2.6 % on another run). Those went to boringtun, which discards
  them, so every `quic-derp-v1` stream lost them, and they slipped past the tunnel shaper.
  Two halves, either of which suffices between two fixed builds: the classifier takes
  WireGuard only with its whole 4-byte header, a type and three zero bytes, which a
  greased packet matches only if its random connection ID also opens on three zero bytes;
  and the DERP endpoints advertise no greasing, so nobody greases toward them
  (`derp_endpoint_config`, [`quic.rs:241`](../crates/tunnel-core/src/transport/quic.rs#L241);
  the measurement is `quic_over_derp_never_clears_the_fixed_bit`,
  [`quic.rs:1140`](../crates/tunnel-core/src/transport/quic.rs#L1140)).
  ⚠️ During a rollout an old peer still advertises greasing, so a fixed build still
  greases toward it, and the old peer still reads by the first byte: the old-to-fixed
  direction is clean at once, the fixed-to-old one once the old end upgrades.
- **A Hive stream has a route of its own (FR-90 P2d-2c).** The tunnel's route is one per
  peer, and the last caller of `tunnel_conn_for` takes it, so a Hive replica stream on it
  would take a `quic-derp-v1` tunnel's route between the same two devices, and a second
  stream between the pair the first's. `hive_conn_for(peer, tag)`
  ([`derp.rs:495`](../crates/tunnel-core/src/transport/derp.rs#L495)) vends a route per
  stream, tagged with its grant's id: its payloads travel as `RMHIVE01` · the 12-byte tag ·
  the packet, and `deliver` splits them off FIRST
  ([`derp.rs:570`](../crates/tunnel-core/src/transport/derp.rs#L570)), so they never reach
  the WG or tunnel consumer. ⚠️ A Hive miss (a tag nobody holds, or a frame cut short) is
  counted in its own `hive_drops` and never reported `Unrouted`, since that event sends the
  runtime after a WG peer to follow. ⚠️ Retirement follows #32's rule: a dropped Hive conn
  clears only its own tag's route, and only while it is still its own sender.
- **The counters are readable (#32).** `drop_counts()` shipped with the signal
  and was surfaced nowhere for a day, so a real 2026-08-25 transition could only
  be argued about from an absence of log lines. `NodeStatus.derp_inbound_drops`
  carries `(unrouted, backpressure)` and `roomler status` prints a `derp drops`
  line when either is non-zero — silent at zero, because a permanent zero line
  is noise, but after a transition `unrouted` is the first thing to read.
  ⚠️ Cumulative since daemon start: **diff two readings**, never judge the
  absolute. ⚠️ And measure on a host whose network actually moves — the
  reference box saw zero.
- **`/derp` recovery walks immediately (#28).** A VPN transition kills the
  `/derp` WS too, and every DERP build attempted while it is down is
  *withheld* — `try_build_derp` refuses over a dead WS, because a carrier born
  there convicts one-way and rebuilds forever. Those peers are carrier-less the
  moment the WS returns, and the establish walk is what re-floors them. So the
  reconnect now wakes the runtime (`MuxEvent::Recovered`, **edge-triggered** so
  the startup `mark_up` is silent): it opens a short fast-walk window and pulls
  the fallback tick into it — the same two levers the netstate-Major lane uses,
  and for the same reason. Without the window `install_peers` runs only every
  6th tick (~30 s); without the pull-forward the window's first walk still waits
  out the 5 s grid. Field 2026-08-24: the WS was back in **1.5 s** and the floor
  took **5 s** more.
- **A DERP carrier no longer convicts under a coturn diagnosis (#28).** It is
  raw WG over the pubkey-addressed `/derp` WS — no allocation, no relayed port,
  nothing to "re-allocate" — yet all four relay death messages asserted TURN
  causes, and pointing "stale coturn port?" at a DERP carrier once sent the
  field hunting through coturn for hours. `kind=` made the truth *available*;
  the sentence now says it. On DERP the one-way cause is specifically **"the
  peer is not reachable over /derp"** — its WS is down, or (pre-#27) it never
  followed us here — which is a different investigation entirely.
- **Resets.** An endpoint change (roam) clears penalties, strikes, and `Q` —
  new endpoints make old evidence stale. Forced-DERP remains a **server
  override**: the monitor annotates the pinned window and never selects
  against it, because only the server can flip both ends of a pair
  atomically.

`ROOMLERD_OVERLAY_PATHMON` (default `on`) now governs only telemetry
verbosity (the 10-min decision summaries); selection is always
monitor-driven — rollback is a release revert, not an env flip.

### Fast failover and return to direct (F0–F4)

Measured end to end by the F0 harness, the ignored test
`overlay::runtime::failover_bench::failover_stall_and_return`. It runs two
relay-mode runtimes, each on its own carrier plane, with a fake control plane
and a fake `/derp`. A test-only blackhole drops every received direct
datagram (both directions dark, `/derp` untouched), and a 50 pps stream runs
each way. The pair is LAN, in one netns, 5 jittered runs per row, with the kill
switches below flipped on one binary:

| | birth → direct | stall (min / median / max) | back on direct after the heal |
|---|---|---|---|
| all switches below off | 30.1 s | 7.3 / 8.0 / 8.1 s | 42.3 / 43.0 / 48.0 s |
| all on, before F2 | 1.3 s | 3.5 / 4.0 / 4.2 s | 4.2 / 4.7 / 4.9 s |
| all on, with F2 standby copies | 1.3 s | 1.8 / 2.0 s (2 runs; 4.1 s with copies off) | 4.5 / 4.8 s |

A 90 s outage came back 40 s after the heal before F3c, and 4 s after it.

**On real WAN pairs (F0-WAN).** The ignored test
`overlay::runtime::failover_bench::failover_wan_node` runs one runtime per
machine: real NICs, real STUN, so two public hosts meet on the fleet-default
srflx tier. A TCP splice on a third host stands in for `/derp` and carries the
hello, the `rc:overlay.srflx` adverts and the run's control words. The fault is
the same blackhole on both planes, 25 s unless noted. In the table, "stall" is
the worse direction, and "after the heal" is when both ends carry the stream
on direct again:

| Pair (direct RTT) | Build | n | birth → direct | stall (min / median / max) | back on direct after the heal | longest gap after the heal |
|---|---|---|---|---|---|---|
| Hyonix HK ↔ Tokyo (43 ms), relay on Isvoro HK | all switches off | 2 | ≈ 5.3 s | 7.6 / 7.9 s | 2.3 / 7.6 s | 59 / 78 ms |
| | all on, before F4 | 5 | ≈ 1.3 s | 1.77 / 2.13 / 2.39 s | 4.0 / 4.5 / 4.8 s | 78–79 ms |
| | all on, with F4 | 2 | ≈ 0 s | 1.97 / 2.23 s | 4.0 / 4.1 s | 78–79 ms |
| | all off, 90 s outage | 1 | ≈ 5.3 s | 8.7 s | 8.3 s | 1.0 s |
| | all on, 90 s outage, before F4 | 1 | ≈ 1.3 s | 2.4 s | 4.0 s | 79 ms |
| aliyun-3 ↔ aliyun-6 (1:1 NAT, security group, 1 ms), relay on a mainland host via ssh tunnels | all switches off | 1 | ≈ 5.3 s | 7.6 s | 7.6 s | 324 ms |
| | all on, before F4 | 6 | ≈ 1.5 s | 1.35 / 1.58 / 2.16 s | 4.0 / 4.2 / 4.8 s | **722–727 ms** |
| | all on, 90 s outage, before F4 | 1 | ≈ 1.5 s | 2.2 s | 4.8 s | 722 ms |
| | all on, with F4 | 3 | ≈ 0 s | 1.84 / 2.24 / 2.34 s | 3.7 / 4.1 / 4.2 s | 40–47 ms |

"Birth → direct" is the settle time minus the harness's 3 s quiet window. F4
does not touch detection, so its stall rows differ from the rows above only by
the jittered cut's sampling (n is small). The mainland pair punched through the
security group from both sides with no inbound rule, which is the srflx tier
doing what it is for.

```mermaid
sequenceDiagram
  participant A as node A
  participant B as node B
  Note over A,B: the direct path goes dark under traffic
  A->>A: business scout (1 s tick): tx up, rx flat, so arm a proof (forced handshake)
  A->>B: unanswered after 0.2 s: data also rides /derp as tagged standby copies (F2)
  A->>A: unanswered after 0.8 s: second initiation (F1)
  A->>A: unanswered at 2 s: RekeyUnanswered, onto the DERP floor, lane opens (F3)
  B->>B: the same, or #27 demote-follow on A's /derp frames
  loop inside the lane (up to 5 min, F3c)
    A->>B: make-before-break probe (LAN spacing 5 s, backing off to 20 s)
  end
  Note over A,B: the path heals: a probe in flight latches on its next 5 s re-send
  B->>B: the responder promotes when A's first direct packet lands
  A->>A: promoted within 100 ms of its latch (F4)
```

| Mechanism | What it does | Kill switch | Where |
|---|---|---|---|
| F1 double tap | a business proof still unanswered after 800 ms gets one more initiation; verdict at 2 s instead of 6 s | `OVERLAY_BUSINESS_POKE_FAST=0` | `lifecycle.rs` `BUSINESS_POKE_*`; `runtime/establish.rs` `scout_business_traffic` |
| F1 recheck | the scout arm re-arms the verdict at the proof's own deadline, not the next 5 s fallback tick | same | `runtime.rs`, `business_scout` arm |
| F3 lane | a `RekeyUnanswered` death on a direct tier opens a 60 s lane: an in-lane srflx/public failure books a 4 s half-life and no strike; `install_peers` walks every 5 s | `OVERLAY_FAST_RETURN=0` | `path.rs` `FAST_RETURN_*` |
| F3b | LAN joins the lane: the spacing pin drops from 60 s to 5 s, with the same short penalty | `OVERLAY_FAST_RETURN_LAN=0` | `path.rs` `lan_spacing` |
| F3c | each in-lane failure extends the lane, up to 5 min after the conviction, doubling penalty and spacing up to 20 s | `OVERLAY_FAST_RETURN_EXTEND=0` | `path.rs` `FAST_RETURN_MAX`, `FAST_RETURN_BACKOFF_CAP` |
| Birth probe | a fresh peer whose first carrier is the DERP floor starts its LAN probe in the same walk, not on the next ~30 s re-upgrade walk | `OVERLAY_BIRTH_LAN_PROBE=0` | `runtime/establish.rs`, floor block of the relay birth branch |
| Fast promote | a latched probe is promoted on the 1 s tick instead of the 5 s fallback sweep | `OVERLAY_FAST_PROBE_PROMOTE=0` | `runtime.rs`, `business_scout` arm |
| F4 probe watch | while a probe is in flight, its latch is checked every 100 ms. The responder promotes as soon as the initiator's first direct packet lands; until the initiator promotes too, its stream still rides `/derp` in the relay carrier's session, which the responder has just replaced. The 1 s scout tick is phase-locked to the 5 s walk that starts the probe, so that dark window was a steady ~0.72 s on the mainland pair | `OVERLAY_PROBE_WATCH=0` (also off with `OVERLAY_FAST_PROBE_PROMOTE=0`) | `runtime.rs` `PROBE_WATCH_TICK`, `probe_watch` arm |
| F2 standby copies | while a proof has gone unanswered for 200 ms, the peer's data is also sent over `/derp`, tagged `STANDBY_MAGIC`; the receiver takes it into the same session through the same ingress gate, and the replay window drops the second of original and copy | `OVERLAY_STANDBY_COPIES=0` | `transport/derp.rs` `STANDBY_MAGIC`; `wg.rs` `StandbyTee`, `decap_standby`; `runtime/establish.rs` `sweep_standby`, `standby_tee_wanted` |

> ⚠️ F2's invariants. A pre-F2 `DerpMux` routes any non-WG payload it cannot
> place as `Unrouted`, i.e. as a demotion that #27 follows. So copies go only
> to a peer whose authenticated disco `STANDBY_HELLO` (kind 0x10, sent on its
> direct carrier, which an older peer ignores) is fresh. That needs no wire
> change. A copy counts in no rx stat: a receiver whose own rx advanced on
> copies would be blind to its own dead direct tx. The tee waits 200 ms for
> the proof's answer, so a healthy one-way stream's recurring proofs copy
> nothing. What is left of the stall is the business scout's 1–2 s detection
> plus that wait.
>
> ⚠️ What F0-WAN does not cover yet:
> - its `/derp` is a TCP splice, not the real relay server and its queueing;
> - every measured host has an endpoint-independent mapping (a public NIC or
>   a 1:1 NAT), so no symmetric or port-restricted NAT has been tested;
> - the fault is a blackhole on receive, not a path that degrades slowly.
>
> F1's 2 s window assumes a direct RTT below about 1 s; on a GEO-satellite
> path the kill switch restores the 6 s window.

## Phase D: the relay tiers

The relay is coturn TURN, optionally upgraded to QUIC-over-TURN. **Single-relay**
(peer → coturn relayed addr → allocation owner) is the primary path and needs
only ONE allocation, which sidesteps the both-allocate hairpin entirely.

The role split is by **UDP capability, not pubkey**: the UDP-blocked side becomes
the **anchor** (it can still allocate over the TURNS/TCP-443 fallback) and the
UDP-capable side becomes the raw-UDP **dialer**. The signal is simply whether the
peer advertised `srflx_endpoints` — a successful STUN round-trip *is* proof that
raw UDP to coturn works, so both ends compute the same roles with no extra wire
field. Pubkey order is only the tie-break when both are UDP-capable.

That leaves exactly one pair the tier cannot serve: **both** ends UDP-blocked —
there is no side left to be the raw-UDP dialer. That case is now covered by
**DERP** (tier D″, shipped default-ON in rc.203): a pubkey-addressed WebSocket
relay at `/derp` on `roomler.ai:443` where **both** peers dial *out* over
TCP/TLS, so no UDP, no inbound reachability, and no coturn permission model is
involved at all. It is NAT-type agnostic by construction. Because a `DerpConn` is
pinned to one peer pubkey, raw WireGuard rides it correctly — unlike single-relay,
which must force QUIC so the anchor can reply to a symmetric dialer's
coturn-observed port. Full protocol, security model, and diagrams:
[`docs/overlay-communication.md`](./overlay-communication.md).

The historic cross-NAT `REKEY_TIMEOUT` on the **both-allocate** fall-through was
root-caused (live coturn diagnostics) as a **worker co-location** failure — the
two allocations landing on *different* coturn workers — not a defect in the
carrier itself: relay-to-relay hairpin and full WG over two same-worker
allocations both verify green. Single-relay avoids it by using one allocation;
DERP avoids coturn entirely.

## Worker co-location — one pick, everywhere (invariant I6)

Any two ends that must meet on a coturn worker MUST select that worker with
the **same function over the same key**. This is an *invariant*, not an
optimisation, for two reasons:

1. **SNAT asymmetry drops cross-worker traffic.** The coturn generic hostname
   is one A record per worker, so each side resolving independently routinely
   lands the two allocations of one pair on different workers. Relay↔relay
   traffic between workers then straddles their public interfaces — and the
   dual-public-IP worker's SNAT asymmetry (buildhost answers from a different
   source IP than the one dialed) breaks it outright: that is the
   both-allocate `REKEY_TIMEOUT` above, and the same failure seen on
   corp↔corp double-relay remote-control sessions (2026-07-14 stall-bursts).
2. **Even where it survives, cross-worker adds a public-internet hop** to a
   path that is already the slowest tier.

Three subsystems make this selection, and since P6 of the overlay
consolidation they share **one implementation** —
`crates/remote_control/src/worker_pick.rs` (`pick_worker_fnv1a`: retain
IPv4 → sort → dedup → FNV-1a 64 of the key `% len`; `pick_index_fnv1a` for
fixed configured lists):

- **overlay broker** (`crates/api/src/ws/overlay.rs`): computes the pick
  authoritatively over a 300 s-cached resolve of the worker set, appends it
  as `&pin=<ip>` to the granted TURN URLs, and hands the *same* result to
  both ends of the pair (the `pair_key` is symmetric by construction);
- **overlay client** (`tunnel-core` `relay_link::pick_worker`): recomputes
  the same pick over its own DNS resolve as the fallback when a grant
  carries no pin;
- **remote-control TURN creds** (`turn_creds::issue_for_session`): orders one
  session-picked worker's URLs first in the creds issued independently to
  controller and agent, so both ICE stacks converge on it.

Agreement is byte-pinned: the shared module and every consumer carry
**golden-vector tests** asserting the same literal picks (grep
`worker-pick golden vector`), so a drifted or re-localised implementation
fails CI rather than splitting pairs in the field. Ops note: source-routing
buildhost's dual-IP SNAT would de-risk failure mode 1 but not obsolete the
invariant — the extra hop (reason 2) remains.

## NAT lab (for field-validating Phase C)

The direct-tier failure modes only reproduce behind real NATs. The lab uses two
throwaway libvirt VMs on the **buildhost** utility host (never a prod cluster node),
each behind its own nftables NAT gateway:

- `masquerade` ≈ endpoint-independent mapping + address-and-port-dependent
  filtering ≈ **port-restricted cone** — the punchable case.
- `snat --random-fully` ≈ **symmetric**.
- low `conntrack` UDP timeouts force the stale-srflx case; `conntrack -F` forces
  a mid-punch mapping rotation.

Server = prod `roomler.ai` (already wire-capable); test daemons run the branch
build via `--config` with `ROOMLERD_OVERLAY_SRFLX=1` set only on them. The
matrix: cone↔cone punches ≤ ~10 s (both `Direct`, zero coturn allocations for
the pair); cone↔symmetric attempts once then relays; symmetric↔symmetric skips
up-front to relay; install skew converges via the re-upgrade tick; stale-srflx
re-trickles; and a same-LAN pair / Phase A path / flag-unset default stay
unchanged. See the P5 VM-field-test recipe for the enrollment + systemd
mechanics.
