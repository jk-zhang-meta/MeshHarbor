# Real-Time Protocols

The server exposes two upgrade endpoints. `/ws` multiplexes three client roles over
one handshake; `/derp` is a purpose-built relay for overlay pairs whose UDP is
blocked in both directions. *As of 0.3.0-rc.381.*

```mermaid
flowchart TB
    subgraph endpoints["wss endpoints"]
        WS["/ws?token=…&role=…"]
        DERP["/derp?token=…"]
    end

    U["Browser (user)"] -->|"no role / role=user<br/>Access JWT"| WS
    A["meshharbord (agent)"] -->|"role=agent<br/>Agent JWT"| WS
    T["meshharbor CLI"] -->|"role=tunnel-client<br/>TunnelClient JWT"| WS
    A2["meshharbord (UDP-blocked)"] -->|"Agent JWT"| DERP

    WS --> H["ws/handler.rs<br/>role → claim validator"]
    H --> UP["user plane<br/>chat · presence · media"]
    H --> RC["rc:* plane<br/>remote control · tunnels · overlay · rpc"]
    DERP --> DR["pubkey-addressed frame relay<br/>tenant-isolated, opaque WG bytes"]
```

Each role is validated against its own JWT audience — a user token cannot open an
agent socket and vice-versa. An optional `tid=<tenant-hex>` query parameter lets the
front load balancer hash tenant-affine connections onto one pod; tokens must match
the claimed tenant (membership-checked for users).

Delivery across pods: WS sessions are pod-local; chat, presence, and notification
events fan out through Redis pub/sub so every pod pushes to its own sockets.

## User plane (browser)

JSON messages, `{"type": "...", ...}`.

**Client → server**

| Type | Purpose |
|---|---|
| `media:join` / `media:leave` | Enter/exit a room call (mediasoup) |
| `media:produce` / `media:consume` | Publish / subscribe a track |
| `media:connect_transport` | DTLS-connect a transport |
| `media:producer_close` | Stop publishing |
| `media:play_audio` / `media:stop_audio` | Bot/audio playback control |
| `presence:update` | Presence state |
| `hive:view.open` / `offer` / `ice` / `renew` / `close` | FR-90 — read an agent session over a viewer peer (module `hive`) |
| `hive:search.open` | FR-90 P2i-2 — search, over a peer of its own, the copies an archive replica holds of the sessions the asker may read; the peer then takes `hive:view.offer` / `ice` / `renew` / `close`, by its grant |
| `ping` | Keepalive |

**Server → client** (consumed by `ui/src/stores/ws.ts`)

| Event | Purpose |
|---|---|
| `message:create` / `update` / `delete` / `reaction` | Live chat |
| `call:message:create` | In-call chat |
| `room:call_started` / `call_ended` / `call_updated` | Call presence on the room list. A `call_ended` the plan's meeting-length cap caused carries `reason: "plan_limit"`, `max_minutes` and `plan` |
| `room:call_ending_soon` | FR-115 P5 — the plan's meeting-length cap (Free: 60 minutes) warns the room's members five minutes before it ends the meeting: `ends_at` (epoch ms), `max_minutes`, `plan`. Shown only to those in that call |
| `typing:start` | Typing indicators |
| `notification:new` / `notification:unread_count` | Notification bell |
| `task:update` | Background-task progress |
| `hive:view.ready` / `refused` / `answer` / `ice` / `renewed` / `closed` | FR-90 — the viewer peer's handshake, addressed to the ONE connection that opened it |
| `hive:search.ready` / `refused` | FR-90 P2i-2 — a search's grant confirmed by its archive replica (with how many sessions it names), or refused; the rest of its handshake is the view's above |

The mediasoup signalling (`media:*`) carries router RTP capabilities, transport
parameters, and producer/consumer ids — the SFU forwards RTP between participants
without decoding it.

The meeting-length cap is a **sweep, not a timer** (FR-115 P5): every pod reads
the calls in progress every 30 s and decides each against the org's plan, and the
two writes it can make — the warning and the end — are conditional on the call it
read, so two pods warn and end a meeting once
(`crates/modules/conference/src/meeting_cap.rs:100`). A timer would have lived in the
pod that started the call and died with it on a rolling deploy. The design, its guards
and its one known gap are in
[FR-115 *Meetings, as built*](fr/FR-115-pricing-reshape.md#meetings-as-built-p5).

The viewer peer's signalling (`hive:view.*`, FR-90) is a view grant and the SDP
and ICE of a **data-only** WebRTC peer between the browser and the device that
holds the session. The server tells the browser `ready` only after the device has
confirmed the grant (FR-83), relays the handshake to and from the one connection
that holds the grant, and never sees the transcript that then flows over the
peer. A search (`hive:search.open`, P2i-2) is a grant of the same kind toward an
archive replica, naming the sessions the asker may read whose copy it holds; its
query and what it finds travel only over its peer. The server's half is
[`crates/modules/hive/src/view.rs`](../crates/modules/hive/src/view.rs), the
device's `agents/meshharbord/src/hive/view.rs`.

## The `rc:*` plane (agents, tunnel clients, controllers)

Defined in `crates/remote_control/src/signaling.rs` (`ClientMsg` / `ServerMsg`,
~60 wire tags). Serialization is **wire-locked by tests**: tags are pinned,
ObjectIds serialize as raw hex, `Permissions` as pipe-separated names. Renaming a
tag is a deliberate wire break.

| Family | Tags | Purpose |
|---|---|---|
| Agent lifecycle | `rc:agent.hello` · `rc:agent.heartbeat` · `rc:agent.update` · `rc:agent.join_org` · `rc:goodbye` | Hello carries caps (codecs, transports, rpc), displays, advertised routes; heartbeat every 30 s; `goodbye` carries a close reason (deleted / replaced / policy) |
| Remote-desktop session | `rc:session.request` · `rc:session.created` · `rc:request` · `rc:ready` · `rc:terminate` · `rc:session.stats` · `rc:error` | Session state machine between controller, server, agent |
| SDP / ICE | `rc:sdp.offer` · `rc:sdp.answer` · `rc:ice` | WebRTC negotiation relayed through the server |
| Consent | `rc:consent` | Owner consent decision (pairs with the HTTP capability URLs) |
| Keepalive | `rc:ping` / `rc:pong` | Application-level liveness |
| Tunnel session | `rc:tunnel.hello` · `.open` · `.opened` · `.terminate` · `.revoked` | Client ⇄ agent tunnel establishment (`open_nonce` correlates concurrent opens; an agent session's `net_grant` rides `.open` from its own device, and `.opened` echoes its id as `net_grant_id`: [tunnels.md](tunnels.md#an-agent-sessions-grant-fr-90-p3-7-2a)) |
| Tunnel TCP flows | `rc:tunnel.tcp.request` → `.forward` → `.accept`/`.reject` · `.half_close` · `.closed` | Per-flow lifecycle |
| Tunnel UDP flows | `rc:tunnel.udp.request` → `.forward` → `.accept`/`.reject` · `.closed` | SOCKS5 UDP ASSOCIATE flows |
| Tunnel carriers | `rc:tunnel.sdp.offer`/`.answer` · `.ice` · `.quic.setup`/`.ready`/`.candidate` | WebRTC-DC and QUIC data-plane negotiation |
| Overlay | `rc:overlay.join` · `.endpoints` · `.srflx` · `.leave` · `.relay_request` → `.netmap` · `.netmap_delta` · `.relay_grant` · `.force_derp` · `.warm_relay_request`/`.warm_relay_grant` | Mesh membership, endpoint discovery, relay coordination |
| Relay / DERP | `rc:relay.regions` · `.probe_report` · `.derp_ticket_request`/`.derp_ticket` | Multi-region PoP selection + ticket auth for standalone DERP relays |
| Fleet RPC | `rc:rpc.exec` · `.cancel` · `.result` · `.request` · `.response` | Remote command execution over the control WS (see [fleet-rpc.md](fleet-rpc.md)) — capability-gated via `AgentCaps.rpc` |
| Overlay key rotation | `rc:agent.key_rotate` → `rc:agent.key_rotated` | An **order** to re-mint the device's overlay key, never a delivery: the order carries no key material (test-locked), the report carries public keys only and is sent on every outcome, refusals included, then re-sent on the next session (see [overlay-key-rotation.md](overlay-key-rotation.md)) — capability-gated via `AgentCaps.rpc` (`key-rotate`), never sent blind |

### Remote-desktop session setup

```mermaid
sequenceDiagram
    participant C as Controller (browser /ws user)
    participant S as Server (Hub)
    participant A as Agent (/ws role=agent)

    C->>S: rc:session.request {agent_id}
    S->>A: rc:request {session, controller, permissions}
    A->>A: consent (auto-grant or LocalAPI/tray prompt, 30 s timeout)
    A->>S: rc:ready
    S->>C: rc:session.created
    C->>S: rc:sdp.offer
    S->>A: rc:sdp.offer
    A->>S: rc:sdp.answer
    S->>C: rc:sdp.answer
    C-->>S: rc:ice (trickle, both directions)
    S-->>A: rc:ice
    Note over C,A: DTLS/SRTP established — video, input,<br/>clipboard, files, apps ride P2P from here
    C->>S: rc:terminate (or agent/server side)
```

Once the P2P link is up, everything else is **DataChannel traffic that never
touches the server**: input events, clipboard chunks, file transfers, the apps
menu, cursor shapes, decoder statistics (`rc:decodestat` feedback that drives the
agent's rate control), and — on the DC render paths — the video bitstream itself.

### Tunnel flow open

```mermaid
sequenceDiagram
    participant T as meshharbor CLI
    participant S as Server (policy)
    participant A as Agent (exit)

    T->>S: rc:tunnel.hello
    T->>S: rc:tunnel.open {agent_id, open_nonce}
    S->>S: ACL policy evaluate (default-deny)
    S->>A: rc:tunnel.open
    A->>S: rc:tunnel.opened
    S->>T: rc:tunnel.opened {session_id}
    par data plane
        T->>S: rc:tunnel.quic.ready + .candidate
        S->>A: rc:tunnel.quic.setup
        A-->>T: QUIC (direct → TURN-relayed → TURNS/TCP :443)
    end
    T->>S: rc:tunnel.tcp.request {dst}
    S->>A: rc:tunnel.tcp.forward
    A->>A: agent-local ACL + dial dst
    A->>S: rc:tunnel.tcp.accept
    S->>T: rc:tunnel.tcp.accept
    Note over T,A: flow bytes ride the QUIC/DC data plane
```

### Overlay join

```mermaid
sequenceDiagram
    participant N as Node (meshharbord / CLI)
    participant S as Server (IPAM + netmap)
    participant P as Peers

    N->>S: rc:overlay.join {wg_pubkey, advertised_routes}
    S->>S: lease overlay IP (pool-first, then cursor)
    S->>N: rc:overlay.netmap {self, peers, cidr, magic_dns}
    S->>P: rc:overlay.netmap_delta {adds}
    N->>S: rc:overlay.endpoints {lan, public} + rc:overlay.srflx
    S->>P: rc:overlay.netmap_delta (endpoint refresh)
    Note over N,P: carriers negotiate per peer:<br/>LAN → public → srflx punch → relay → DERP
    N->>S: rc:overlay.relay_request (only if needed)
    S->>N: rc:overlay.relay_grant {worker, creds}
```

## DERP

`GET /derp?token=<agent-jwt>` upgrades to a minimal frame relay for overlay pairs
where **both** sides are UDP-blocked:

- Frames are `[dst_pubkey(32) || payload]` client→server, rewritten to
  `[src_pubkey(32) || payload]` on delivery.
- Hard tenant/network isolation; the payload is WireGuard ciphertext the relay
  cannot read.
- Standalone regional PoPs (`crates/derp-relay`) run the same protocol DB-free,
  authenticated by Ed25519 tickets minted over `rc:relay.derp_ticket_request`.

## Connection hygiene

- Agents keep one outbound WSS control link: WS ping every 25 s,
  `rc:agent.heartbeat` every 30 s, exponential reconnect capped at 60 s; a 401 on
  upgrade is fatal (re-enroll).
  - The ladder restarts at 1 s when a connection that sent its hello lived ≥ 30 s
    and then dropped (#2221). Before that, a successful reconnect kept the
    ladder where the outage left it, so the next ordinary drop waited out the
    PREVIOUS outage's step (8 s in the field after a pod roll; up to 60 s).
  - A server that accepts and drops at once still climbs the ladder. That 30 s
    bar is what keeps a flapping server from drawing a fleet-wide reconnect
    every second.
- Agents also enforce **receive-liveness**: no inbound frame for 80 s ⇒ reconnect —
  this heals half-open sockets that TLS-inspecting middleboxes keep artificially
  alive.
- `rc:goodbye` close reasons distinguish *replaced by newer connection* (benign
  restart) from *deleted / policy-rejected* (stop retrying).
