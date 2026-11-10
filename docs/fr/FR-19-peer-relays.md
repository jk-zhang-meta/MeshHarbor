# FR-19: Peer relays — tenant-owned UDP relay nodes between direct and DERP

Status: **P0–P4c field-verified** — shipped through **0.4.20** (`agent-v0.4.20`); the whole path is proven on the primary tenant: **CORPLAP-3↔mars carried real traffic on `relay:org/udp` (~84 ms) via the scw-m2-asahi relay** (`forwarded=128`), then torn down on revoke back to the DERP floor. Capability + gates + mint + forward + revoke all field-verified 2026-08-29; live behind `overlay_org_relay` + `peer_relay_mode`, default off. **27 of 29 criteria as of 2026-09-24**: the relay socket census ticked once FR-48 fixed the TURN client's leak, and the docs criterion was added retroactively and met by [`docs/peer-relays.md`](../peer-relays.md). The two still open are **decisions for the operator, not measurements**: the pre-FR-19 forward-compatibility box (#811's `unknown_relay_strategy_tag_keeps_the_whole_netmap_parseable` already asserts the parser tolerance its note calls unasserted) and the `peer_relay_mode=off` before/after diff (no pre-FR-19 build is left in the fleet to diff against). Proposed 2026-08-28. Tracking issue: [`FR-19` (#805)](https://github.com/jk-zhang-meta/MeshHarbor/issues/805).
Reference design: [Tailscale peer relays](https://tailscale.com/docs/features/peer-relay).
Sibling of FR-18 (#801) and FR-17 (#799) — both are about the *cost* of the relay path;
this FR is about **replacing that path with a better one** rather than tuning it.

> **Revision note (2026-08-28).** This spec was independently reviewed on three lenses
> before publication — protocol correctness, security, and test/fleet-ops — and the first
> draft did not survive it. Three things changed materially and are called out where they
> land: the carrier is a **third `RelayKind`, not a fifth tier** (§6); the bind handshake
> was **unauthenticated** as first drawn and is now keyed (§4); and the port decision is a
> **hypothesis pending E2E-3**, not a finding (§2b). The wrong turns are kept in place
> rather than quietly deleted, because each is a trap the implementer would otherwise
> re-enter.

---

## MeshHarbor arbitrary-hop continuation — acceptance still open

The historical P0–P4c result above covers the original peer-relay release. It
does not establish completion of MeshHarbor's arbitrary-hop routing and trial
continuation. That work remains in development until coordinated rollout and
field verification pass.

The continuation keeps one ordered, loop-free relay path and its requester
orientation through discovery, trial admission, delivery, commit and return.
Every relay and actual cross-region edge is authorized from current evidence;
the control plane continues to carry no application plaintext. Computation and
page budgets must allow a discovery scan to resume, rather than permanently
hide a valid path beyond the first budget window. Existing peer-relay and
backbone controls remain the operational gates; no second compatibility mode
or fixed hop limit is part of this continuation.

The current acceptance oracle is:

- [ ] Production discovery and the actual client enumerate distinct paths with
  shared first/last relays, resume after budget exhaustion, and refresh revoked
  candidates without reusing stale authority.
- [ ] The client-generated complete path reaches the unified trial engine;
  a Start with the same request ID but different intermediate relays is rejected.
- [ ] Three- and four-relay encrypted traffic survives bilateral commit;
  bilateral return releases all relay/bridge reservations and blocks retired data.
- [ ] Unknown region evidence refuses a new affected trial while retaining a
  healthy established session; confirmed identity or connection-rule violations
  still revoke the exact session generation.
- [ ] The combined implementation passes review and its build, client, actual
  request, rollback and data-plane checks on the exact release candidate.
- [ ] Server and node rollout, real network/NAT behavior, fallback, and operator
  management access are verified in the field with a recoverable release.

Local library and isolated WS/WireGuard results are development evidence. They
do not tick the combined or field criteria above, and do not change the older
release's historical status. Detailed mutable attempts and review conclusions
remain in the task's handoff/evidence records rather than this specification.

## Goal

Let an org nominate one of its own enrolled nodes as a **peer relay**: a `meshharbord` that
forwards *ciphertext* between two other nodes of the same tenant over UDP, on a port the
operator chose, without decrypting anything and without the meshharbor control plane in the
data path at all.

```
LAN → direct-public → srflx hole-punch → relay{ ORG | TURN | DERP }
```

Three things this buys, in priority order:

1. **The API pod stops carrying video.** Today a relayed carrier is `relay:derp/tcp` —
   frames cross the `meshharbor2` pod, the same process serving HTTP, WS and mediasoup. That
   is in direct tension with the standing invariant in `CLAUDE.md`: *"The server
   coordinates but never carries plaintext… any design that would make the control plane a
   data path is wrong on those grounds alone."* DERP **is** that design, accepted as the
   **floor**. An org relay is the same escape hatch without the control plane in it.
2. **HQ-owned relaying** — an org with a well-connected headquarters box relays its branch
   and remote devices through *its own hardware*. See [§12](#12-hq-deployment--the-primary-use-case),
   which also states plainly what the relay operator **learns** — that half is not a
   footnote, it is a consequence of the deployment.
3. **Latency and throughput.** Tailscale's published result for the equivalent change:
   **2.24 → 27.5 Mbit/s (12.5×)**, **452 → 298 ms**
   ([blog](https://tailscale.com/blog/peer-relays-international-networks)).

**Non-goal, stated up front:** this does not replace DERP and must not be able to. DERP
over TLS:443 stays the floor (design commitment #2), and `CORPLAP-2` is why
([§2b](#2b-what-the-sweep-does-and-does-not-establish)).

---

## 2. Why now — field evidence, measured before any code

Taken **2026-08-28 from mars over Fleet RPC**, fleet at 0.4.10, before this spec was
written.

### 2a. Who is on the relay today

`sudo mh peers` on mars, primary org, online peers:

| peer | carrier | RTT |
|---|---|---|
| `CORPLAP-3` | **`relay:derp/tcp`** | 45 ms |
| `CORPLAP-2` | **`relay:derp/tcp`** | 56 ms |
| `neo16-wsl-2` | **`relay:derp/tcp`** | 42 ms |
| neo16, jupiter, zeus, CORPLAP-1, rozalina-2, scw-m2-asahi, macbook-pro | `direct` | 0–137 ms |

Three of twelve online peers are relayed and every one is on **TCP** — a whole
head-of-line-blocking layer *below* the SCTP one FR-17 is about, on top of the 512-frame
`OUTBOUND_QUEUE` (`crates/tunnel-core/src/transport/derp.rs:53`) FR-18 measured at ≈1.8 s.

### 2b. What the sweep does — and does not — establish

`mh netcheck` across the fleet, same session:

| host | `stun/udp` | `relay band/udp` | NAT | role here |
|---|---|---|---|---|
| **mars** | ok | **reachable** | cone | ✅ relay server — utility tier, public IP |
| **jupiter** | ok | **BLOCKED** | cone | relay server *only after host-firewall provisioning* |
| **zeus** | ok | **BLOCKED** | cone | relay server *only after host-firewall provisioning* |
| **CORPLAP-3** | ok | **BLOCKED** | **symmetric** | ✅ **client** — the target population |
| **CORPLAP-2** | **NO MAPPING** | *(derived, not probed)* | untyped | ❌ UDP is dead; stays on the DERP floor |
| CORPLAP-1 | ok | reachable | cone | already direct |
| scw-m2-asahi | ok | reachable | cone | already direct |

**Established:**

1. **`CORPLAP-3` is the proof the feature is worth building.** Its NAT is *symmetric* —
   which is why direct fails and why no amount of hole-punching will ever fix it — and its
   STUN/UDP works. A relay on a port it can reach is precisely and only what it needs.
2. **`CORPLAP-2` is the proof DERP must stay.** `stun/udp: NO MAPPING` means no UDP path at
   all. No relay on any port helps it. ⚠️ Note its `relay band` cell is **derived, not
   measured**: `run_measurement` short-circuits `if !stun_udp { Some(false) }`
   (`crates/tunnel-core/src/overlay/netcheck.rs:205`). Marked as such because this spec's
   own §8 rule is that absence of measurement is never evidence of absence of capability.
3. **A high UDP port is a real risk** on the corp-managed hosts, and the codebase already
   says so: `crates/remote_control/src/signaling.rs:5288` — *"a corp egress that whitelists
   STUN:3478 still drops the ~10-13k relay band."*

**NOT established — the port choice is a hypothesis, not a finding.** ⚠️ An earlier draft
of this spec claimed *"UDP/3478 passes and 49152–65535 does not"* and presented the default
port as decided "on the strength of §2b". That overreads the instrument in two ways:

- `relay_band_udp` probes **coturn's configured relay band** (the comment above puts it
  around 10–13k), and it **never touches 40000**. A host that drops 10000–13000 may or may
  not drop 40000.
- The probe is not even a port test in the general case — see
  [§5](#5-port-selection--a-hypothesis-e2e-3-must-settle).

So: 3478 was the **starting hypothesis**, and **E2E-3 has now decided it — confirmed**. See
[§5](#5-port-selection--settled-by-e2e-3-3478) and the field log.

### 2c. jupiter and zeus will repeat the FR-4 failure if we let them

Both cluster hosts report `relay band/udp: BLOCKED` — their own host firewall, generated by
Ansible in `~/k8s-cluster-multi`. FR-4 (#776) is the cautionary tale, verbatim from
`CLAUDE.md`: the playbook *"flushes and rebuilds the COTURN chains — never hand-fix a host
without also fixing the vars, or the next playbook run reverts it."* Conference media was
dead on zeus for **weeks**, silently, for a hash-determined subset of tenants.

**Provisioning is therefore a phase (P5), not a manual prerequisite** — with the disruption
that phase itself causes stated honestly in [§10c](#10c-e2e-on-the-real-fleet--mars-zeus-jupiter).

---

## 3. The reference design (Tailscale), for orientation

Verified against `tailscale.com/net/udprelay` and `tailscale.com/disco`.

| element | Tailscale |
|---|---|
| Session identity | 32-bit **VNI**, allocated per ordered pair of disco public keys |
| Framing | **Geneve** (RFC 8926); `Control` bit separates handshake from data |
| Allocation | `AllocateEndpoint(discoA, discoB)` → `ServerEndpoint{ServerDisco, ClientDisco, LamportID, VNI, BindLifetime, SteadyStateLifetime, AddrPorts}`; idempotent per pair. **Reached over a control-plane-authenticated RPC**, not from an inbound UDP packet |
| Ordering | **`LamportID`**, a server-wide logical clock |
| Bind handshake | 3-way and **disco-sealed (NaCl box)** — `BindUDPRelayEndpoint` (0x04) → `…Challenge` (0x05) → `…Answer` (0x06). The sealing is what proves the binder holds the invited party's key |
| Challenge | BLAKE2s MAC over `vni ‖ generation ‖ invited-party key ‖ addr:port`, checked against the current *and previous* rotation window |
| Anti-tamper | The VNI is repeated *inside* the sealed payload, so a rewritten Geneve header is detected |
| Lifetimes | `defaultBindLifetime = 30 s` (3 legs × 10 s), `defaultSteadyStateLifetime = 5 min` idle |
| Forwarding | `addr:port` swap keyed by VNI once both `boundAddrPorts` are set |
| Authorization | ACL grant `tailscale.com/cap/relay` |
| Requirements | v1.86+ both ends; relay role unavailable on iOS / tvOS / Android |

⚠️ **Attribution correction.** An earlier draft presented "stateless MAC over the source
`addr:port` under a rotating secret, accepted for the current and previous window" as
copied-from-Tailscale prior art and called statelessness *"the single most important
security property to preserve."* That construction is **WireGuard's cookie-reply design**
(whitepaper §5.4.7), and it is defended here on its own merits, not on borrowed authority
— because Tailscale's allocation happens at an authenticated RPC, its relay has per-session
state before any UDP arrives, and so does ours (§1 step 3). **Statelessness is therefore a
DoS mitigation on the bind leg, not the security foundation.** The foundation is §4's key.

The two properties genuinely worth copying: **ciphertext-only forwarding** (the relay is
not a trust boundary) and **an authenticated bind** (§4).

### 3a. Wire — framing, and the socket it lives on

**The relay listens on its own dedicated UDP port** (§5), not on the node's overlay socket.
⚠️ An earlier draft said both in different sections; the dedicated port is the design,
because it means only relay traffic arrives there and the client side attaches through the
existing `RelayConn` seam (§6) rather than the shared carrier plane.

Framing is Geneve (RFC 8926) with the **`Opt Len` field pinned to 0** — a normative wire
invariant, enforced on receive. Two independent reviews landed on the same defect in the
first draft's claim that demux is *"unambiguous without a magic number"*; it is not:

| Geneve byte 0 | collides with |
|---|---|
| `0x00` (Opt Len 0) | STUN's first byte — separated only by `has_stun_cookie` requiring `pkt[4..8] == 0x2112A442`, and Geneve bytes 4–7 are **VNI(24) ‖ Reserved(8)** |
| `0x01`–`0x04` (Opt Len 1–4) | **WireGuard types 1–4, every one of them** |

What actually keeps WireGuard disjoint on the existing plane is a **four**-byte test —
`is_wg_shaped` (`crates/tunnel-core/src/overlay/wg.rs:2413`) requires `pkt[1..4] == 0`, and
Geneve's bytes 2–3 carry a nonzero Protocol Type. One byte is not enough, and
`payload_is_wg_or_disco` (`crates/remote_control/src/derp_frame.rs:39`) classifies on the
first byte alone.

So the rules are:

1. `Opt Len` **MUST** be 0; a frame with options is rejected, not parsed.
2. The Protocol Type is pinned to a fixed non-zero value, keeping bytes 1–3 non-WG-shaped.
3. **`VNI = 0x2112A4` is never minted**, so a relay frame can never present the STUN magic
   cookie at bytes 4–7.
4. Disjointness is proven over **WG × STUN × disco × Geneve**, table-driven — the standard
   `disco.rs:45-52` already sets: *"Shape disjointness (load-bearing — a false match steals
   a live datagram and blacks out the mesh)"*, locked by
   `disco_shape_is_disjoint_from_wg_and_stun`.

⚠️ The Geneve choice is **not** justified by tooling. An earlier draft claimed every capture
tool dissects it; in practice Geneve's Protocol Type is an EtherType, so Wireshark dissects
the 8-byte header and then fails on a payload that is not an Ethernet frame. Geneve is kept
for fixed offsets, a control bit and an option escape hatch — nothing more.

**The relay holds no key that decrypts anything.** It forwards WireGuard ciphertext between
two bound `addr:port`s selected by VNI.

### 3b. ⚠️ A new `RelayStrategyWire` tag would black-hole netmaps on every fielded agent

**This is the one change that can break the fleet silently. It ships first, alone, as P0.**

`RelayStrategyWire` (`crates/remote_control/src/signaling.rs:3021`) documents itself as safe
to extend — *"an unknown/absent value ⇒ the client falls back to its local computation, so
adding a variant later is forward-compatible"* (`:1976-1978`). **The comment is wrong about
the "unknown" half and the code does not implement it.** The enum is a plain
`#[derive(Deserialize)]` with `#[serde(rename_all = "kebab-case")]`, **no `#[serde(other)]`**
and no custom decoder. `#[serde(default)]` on `NetmapPeer.relay_strategy` (`:2117`) handles a
*missing* field, not an *unrecognised* one. An unknown tag is a hard serde error failing the
**entire enclosing `ServerMsg`**, and the agent's parse arm swallows it at `debug!`
(`agents/meshharbord/src/signaling.rs:1543`).

Add a variant carelessly and every pre-FR-19 agent **drops whole netmap frames** and stops
installing peers — a fleet-wide outage delivered by the server, visible only at `debug!`.

Four requirements, all in P0:

1. A **`supports_org_relay` hello bit** (`#[serde(default)] bool`, the shape of
   `supports_server_relay_strategy`, `signaling.rs:2208`), gated at the existing both-ends
   gate in `server_relay_verdict` (`crates/api/src/ws/overlay.rs:1877`). The gate is
   **permanent**, not "until everyone upgrades".
2. `#[serde(other)] Unknown` (or a `deserialize_with` mapping unknown → `None`), making the
   documented behaviour real. **This is a bug fix worth landing even if FR-19 never ships.**
3. The variant stays a **unit variant**. The session is pushed **out-of-band** as its own
   `rc:overlay.relay_session` message keyed by node id. ⚠️ `RelayStrategyWire` derives
   **`Copy`** (`:1985`); a `session` payload would break that derive and ripple through
   `netmap.rs:92`, `relay_link.rs:1039-1042` and three by-value returns at
   `overlay.rs:1855/1876/1954` — and would also change the JSON from a string tag to a map.
4. A test decoding `"org-relay"` against a **pre-FR-19 `NetmapPeer` shape**.

---

## 4. The bind handshake — authenticated, then anti-spoof, then anti-amplification

⚠️ **The first draft of this spec was insecure here, and it is worth stating exactly how,
because the mistake is easy to repeat.** It drew:

```
client ──Bind{vni, generation}────────────────────────────▶ relay
client ◀─Challenge{ MAC(vni‖generation‖peer_pubkey‖addr:port) }── relay
client ──Answer{ challenge echoed }───────────────────────▶ relay   ⇒ bound
```

The client's only obligation there is to **echo a value the relay just sent it in the
clear**. That proves it can receive at an address — return-routability — and nothing else.
It copied the anti-DoS half of Tailscale's handshake and dropped the **disco-sealing**,
which is the half that proves identity. Consequences: the VNI is 24 bits and not secret, so
blind guessing against a relay holding ~1 000 sessions hits at ~6×10⁻⁵ per probe; the
pubkey in the MAC input is public netmap data; and anyone sharing the victim's egress
`addr:port` — *a co-worker behind the same corporate NAT, i.e. exactly the `CORPLAP-3`
population this FR targets* — can take the slot. A stolen bind black-holes the pair,
receives the counterparty's ciphertext, and injects arbitrary UDP at its WireGuard socket.

⚠️ The first draft also cited `crates/api/src/ws/derp.rs:351` (the key-equality assertion on
DERP registration) as the precedent to copy — but that check works **because the WebSocket
underneath it is already authenticated** by the agent JWT (`derp.rs:234` `verify_agent_token`,
`:247` tenant match, `:284` refusal check). Copying the assertion without the channel copies
a check whose authentication came from somewhere else.

### The design

Three layers, each doing one job:

**(1) Authentication — a per-member secret delivered over the authenticated control WS.**
The mint already reaches both nodes on their agent WS (§1 step 3). It carries a
per-`(session, member)` `bind_secret`; the relay receives both in its copy of the mint.

```
client ──Bind{ vni, generation, nonce, tag₁ }─────────────▶ relay
                tag₁ = MAC(bind_secret, DOMAIN ‖ vni ‖ generation ‖ nonce)      ← no address, see below
client ◀─Challenge{ nonce, cookie }───────────────────────▶ relay
                cookie = MAC(cookie_key, DOMAIN ‖ vni ‖ nonce ‖ addr:port)
client ──Answer{ nonce, cookie, tag₂ }────────────────────▶ relay   ⇒ bound
                tag₂ = MAC(bind_secret, DOMAIN ‖ cookie ‖ nonce)
```

**Two keys with two different jobs, never derived from one another:**

| key | held by | proves |
|---|---|---|
| `bind_secret` | the **member** and the relay | *you are the node this session was minted for* |
| `cookie_key` | the **relay only**, rotating | *you can receive at the address you claim* |

**(2) Anti-spoofing** — the rotating cookie, accepted for the current and previous window,
so the relay keeps no per-attempt state. Rotation period ≤ the 30 s bind lifetime.

**(3) Anti-amplification** — ⚠️ **the bind path answers unauthenticated packets by design,
on UDP/3478, which is already among the most-sprayed reflection ports on the internet.** The
repo's own rule is stated at `crates/tunnel-core/src/overlay/disco.rs:69-70`: *"a reply is
exactly this long too, so the responder can never amplify (reply bytes == request bytes)"*,
implemented as a fixed `FRAME_LEN = 85`. FR-19 adopts it: **`Bind` is padded so
`len(response) ≤ len(request)`**, and an acceptance criterion asserts the ratio. Without
this, a customer's HQ box is a DDoS reflector at roughly 3×.

Plus a **per-source bind-attempt limiter** modelled on `unknown_init_fresh`
(`crates/tunnel-core/src/overlay/carrier_plane.rs:705`; `UNKNOWN_INIT_MIN_INTERVAL = 2 s`,
`UNKNOWN_INIT_MAX_SOURCES = 64`, `wg.rs:716`), with a counter and a reader.

### Construction details that are security-relevant

- ⚠️ **`tag₁` covers no address — corrected in P2c.** The first implementation of
  P2a (#881) put the observed `addr:port` into `tag₁`, matching an earlier draft of this
  section. The loopback test made the mistake obvious within minutes: **a client behind
  NAT cannot know its own mapped `addr:port` when it sends its first packet**, so it could
  never compute the value the relay expected — the handshake was unimplementable for
  exactly the population it exists for. The reference design binds the address at the
  *challenge* step for this reason, and so does this one now: the cookie covers the
  observed source, `tag₂` covers the cookie, and the relay re-derives the cookie against
  the observed source on the answer. The address is bound *by step 3*, the only step that
  grants anything. Cost: a captured `tag₁` replayed from elsewhere earns one 64-byte
  challenge to the replayer's own address, rate-limited — the posture of a probe echo,
  and it grants nothing. Tested in both directions.

- **`generation`** is the mint's monotonic re-issue counter for a `(pair, relay)` — defined
  here because an earlier draft used it inside a MAC without defining it anywhere.
- **A per-attempt random `nonce`**, echoed and MAC-covered, so a captured exchange does not
  replay for the rotation window (doubled by accepting the previous window).
- **Fixed-width or length-prefixed encoding with a `DOMAIN` separation constant.** Naive
  concatenation of a textual `addr:port` and a variable-width integer lets distinct tuples
  serialise identically (IPv4 vs IPv6 forms; digits sliding into the adjacent field).
- **Constant-time comparison, using `subtle`.** ⚠️ Every MAC compare in this tree today is a
  plain slice compare — `disco.rs:222` (whose comment says *"Constant-time-ish"* and is not),
  `wg.rs:2452`, `derp.rs:351`. For WireGuard's `mac1` that is defensible; its own doc calls it
  *"a ROUTER's pre-filter … not an authenticator"*. Here the MAC **is** the authenticator, so
  "model it on the existing one" would propagate the defect.
- **Membership.** A node may bind only into a session naming its own key in `members`.
- **Re-bind is permitted only under a valid `tag₁`.** ⚠️ This is load-bearing in *both*
  directions: forbid it and a symmetric-NAT host that rebinds its mapping — `CORPLAP-3`,
  the target population — loses its session with no recovery short of a control-plane
  re-mint, the round trip this feature exists to avoid; permit it unauthenticated and it is
  a hijack primitive. The overlay already models this event (`Carrier::set_direct_dst`,
  `wg.rs:238`, repoints on cryptographic evidence; `Routed::SessionRoam`,
  `carrier_plane.rs:766`). Re-bind keeps the same VNI and updates one `boundAddrPort`.

### Lifetimes

**30 s** to complete the bind, **5 min** idle, and an **absolute `max_lifetime`**
independent of idle refresh. ⚠️ The absolute bound is not optional: `idle_deadline` is
*refreshed on traffic*, and with a 25 s WireGuard persistent keepalive
(`wg.rs:51 KEEPALIVE_SECS = 25`) it **never fires while a carrier is installed**. Without a
`max_lifetime` an active session has no expiry at all, and capacity is governed solely by
mint policy and `relay_max_sessions`.

**The relay re-clamps every deadline against its own clock** and its own ceilings — server
timestamps may only *shorten*. This is the MeshHarbor SSH rule (`CLAUDE.md` P5: *"Agent
re-clamps the grant against its OWN clock"*), and it matters more here: the spec's own soak
tooling records CORPLAP-1 running **21.4 s** behind the dev box, against a 30 s bind deadline
compared across three hosts.

---

## Key design

### 1. The relay is a role of `meshharbord`, offered by the server, never assumed by a node

`CLAUDE.md` commitment #1: *"Best carrier that works, always measured, never assumed…
chosen by a **server verdict over measured `CapVector`s**. Heuristics may detect; they never
decide."*

1. A node opts in locally (`relay_server_enabled`, `relay_server_port`) and advertises the
   capability verb `relay-server` through `models::RpcCap` — variant → `wire()` arm → `ALL`
   entry. ⚠️ Equality matching only: `relay` is a prefix of `relay-server`, the
   `ssh`/`ssh-consent` trap. (`RpcCap::ALL` is `[RpcCap; 6]` at `models.rs:326`, a
   fixed-size array — the **compiler** forces the entry, not a test.)
2. An admin approves the device — the offer is not the grant (§2, gate 3).
3. The **server** mints the session and pushes it to both nodes plus the relay.
4. The nodes bind, measure, and report.

Verdict machinery to extend, verified against master:

| what | anchor |
|---|---|
| Server verdict entry point | `crates/api/src/ws/overlay.rs:1851` `server_relay_verdict` |
| …delegating to the pure decision | `overlay.rs:1944` `relay_verdict_core` |
| Measured caps supersede presence | `overlay.rs:1893-1902` (in `verdict_from_nodes`, `:1872`) |
| Wire verdict enum | `crates/remote_control/src/signaling.rs:3023` `RelayStrategyWire` |
| Client-side cascade consuming it | `crates/tunnel-core/src/overlay/relay_link.rs:1016` `relay_strategy` |

### 2. Gates — and an honest account of which are actually armed

```
PeerRelaySession {
  vni:           u24,             // GLOBALLY unique per relay node — see below
  relay_node:    ObjectId,
  tenant_id:     ObjectId,        // stored in the relay's entry, not encoded in the VNI
  endpoints:     Vec<SocketAddr>, // measured + static, SSRF-validated (§5)
  members:       [(WgPublicKey, BindSecret); 2],
  generation:    u64,
  lamport:       u64,             // server-owned
  bind_deadline / idle_deadline / max_lifetime
}
```

⚠️ **VNI scoping — the first draft was self-contradictory** (`// unique within the relay
node, per tenant`, then *"the VNI space is per-tenant-scoped"*). Those are mutually
exclusive: per-tenant allocation on a shared node lets two tenants hold the same VNI, and
the Geneve header has no tenant field, so the relay's demux key is ambiguous across exactly
the boundary that matters. **The VNI is globally unique per relay node**, and `tenant_id`
lives in the session entry. This is the lesson the carrier plane already learned in the
opposite direction: `alloc_index` is *"a process-unique 24-bit session index"*
(`carrier_plane.rs:1000`) precisely because *"with N orgs on one socket, a source-keyed table
cannot tell them apart"* (`:13-21`). It is also typed **`u24`**, not `u32`: the wire field
is 24 bits, so two `u32`s differing above bit 23 would alias to one session.

| # | gate | owner | actual default |
|---|---|---|---|
| 1 | `OverlayNetwork.peer_relay_mode` (`off`\|`warn`\|`on`) | the org | **`off`** ✅ |
| 2 | overlay ACL `relay` capability, src → relay node | the policy author | ⚠️ **inert today** |
| 3 | `Agent.peer_relay_policy` — approval needs `MANAGE_AGENTS` **and** `EXEC_DEVICE` (see ⚠️ under *Permissions*) | the fleet admin | **deny** ✅ |
| 4 | agent-local `relay_server_enabled` | the device owner | **off** ✅ |

⚠️ **Gate 2's default is not "deny" — it is "off, and permits everything."** The first draft
claimed four default-deny gates; there are three. `OverlayAclMode` derives `#[default] Off`
(`crates/remote_control/src/models.rs:1815`), documented as *"every node sees every peer…
The default, so enabling the feature never breaks a live mesh"*; `Warn` *"ship[s] the
permissive netmap"*; and `CLAUDE.md`'s own open-issues list records that **nothing has ever
run under `enforce` in the field**. Tailscale's `cap/relay` is an *affirmative grant*; a
mode-conditioned visibility shaping is not the same thing. Two options, and this FR takes
the first:

- **(taken)** the relay grant is an **affirmative capability evaluated regardless of
  `acl_mode`** — the honest analogue of `cap/relay`;
- (rejected) leave it mode-conditioned and document that gate 2 is inert until a tenant
  reaches `enforce`.

⚠️ **"Fail closed" is not implementable through the API the first draft prescribed.**
`load_acl` returns `AclCtx` — **not** `Result` — and its error path returns `AclCtx::off()`,
logging *"failing OPEN"* (`overlay.rs:1770-1773`, `:1786`). That is byte-identical to a
tenant that genuinely has ACLs disabled, so a caller shaped like the existing precedent
(`overlay.rs:719-743`) takes the "no ACL configured" branch on a Mongo blip and **grants**,
while its author believes it fails closed. Required: a `try_load_acl(…) -> Result<AclCtx, _>`
for the new gate, with the two existing callers keeping their posture via an explicit
`.unwrap_or_else(|_| AclCtx::off())` — which also turns their fail-open into a visible
decision. Same for `overlay_source_of` (`overlay.rs:1793`), which swallows both errors
(`.ok()` → `owner_user_id: None`; `unwrap_or_default()` → empty roles), silently failing to
match a `UserId`/`RoleId`-scoped grant with no log — against `feedback_log_every_silent_drop`.

**Permissions.** ⚠️ Exit-node approval requires `MANAGE_AGENTS`
(`crates/api/src/routes/overlay_route.rs:310`, checked at `:328`), which **is** in `DEFAULT_ADMIN`
(`crates/db/src/models/role.rs:104`), and writes no audit row. Nominating a relay makes a
device a traffic chokepoint and a metadata observation point for the whole tenant (§12), so
it belongs in the class `role.rs` already draws a line around — *"an admin should see every
command the fleet ran without silently gaining the power to run one"*, which is why
`EXEC_DEVICE` (1<<27) and `SSH_DEVICE` (1<<29) are excluded. Therefore:

⚠️ **Corrected in P3a (2026-08-29): there is no free permission bit, so there is no
`RELAY_DEVICE`.** The spec and its security review both assumed bits 31 and 32 were
available. They are not: the UI mirror (`ui/src/utils/permissions.ts`) checks masks with
JavaScript's **signed 32-bit** bitwise ops — `1 << 31` is negative, `1 << 32` wraps to 1 —
and its spec pins the ceiling at bit 30 *by design*. A bit defined server-side that the UI
cannot render is a permission nobody can grant from the product, which is worse than no
bit. So, until the mask moves to `BigInt` (#888):

- **Relay approval requires `MANAGE_AGENTS` and `EXEC_DEVICE`.** Coherent rather than a
  hack: an `EXEC_DEVICE` holder can already run `mh config set relay_server_enabled
  true` on any exec-enabled device as root, so the coupling grants nothing new. What it
  cannot express is an org that wants relay approvers who may *not* run root commands —
  that needs the dedicated bit, which needs #888.
- **The relay audit reads behind `VIEW_EXEC_AUDIT`**, keeping the exec pairing.

The bullets below describe the design *once #888 lands*:

- **`RELAY_DEVICE`** — approval; **not** in `DEFAULT_ADMIN`; required *in addition to*
  `MANAGE_AGENTS`.
- **`VIEW_RELAY_AUDIT`** — in `DEFAULT_ADMIN`, mirroring `VIEW_EXEC_AUDIT` (1<<28) and
  `VIEW_SSH_AUDIT` (1<<30).
- ⚠️ `ALL = (1 << 31) - 1` (`role.rs:133`) must be bumped in the same commit;
  `all_contains_every_named_permission` will force it.
- **The approval itself is audited** — it is the privilege-granting action, and the
  exit-node precedent auditing nothing is a gap to not copy.

**Rate limiting.** ⚠️ `handle_overlay_relay_request` has **none** — `crates/api/src/ws/overlay.rs`
contains zero `RateLimiter` references. Both precedents this FR claims equivalence with do
enforce one, deliberately after the identity gates so refusals are attributable:
`agent_exec.rs:320` (30/min) and `agent_ssh.rs:541` (20/min). `CLAUDE.md` records why:
*"The HTTP `tower_governor` is per-IP and never saw the device-originated
`rc:rpc.request` / `rc:ssh.request` WS legs, so those had no ceiling at all."* A mint is
another device-originated WS leg and is **more** expensive, because it writes state onto a
*third* device. Add a `(requesting node, relay node)` limiter with a `RateLimited` deny
reason. **P3b:** `AppState::relay_rate_limiter` + `peer_relay_limits::MINT_RATE_LIMIT_PER_MINUTE`
= 30 (the exec precedent, so a fleet boot — one requester asking for every unreachable peer
through the same relay inside a minute — fits under it); the check site lands with the mint
in P3c, after the identity gates, so a refusal is attributable and audited.

**Multi-org: relay serving is PRIMARY-ORG ONLY, enforced.** ⚠️ The first draft said a device
*"may serve N tenants"* and, two sentences later, that it *"should follow"* the primary-only
rule. `docs/multi-org.md:260` makes exit-node and netstack primary-only because they are
**host-global singletons**; a UDP listener on a host-global port is exactly that. And
`:106-108` adds the trust half for `rc:agent.update`: *"a secondary org's admin must not be
able to force-update a shared binary"* — a secondary org's admin minting sessions onto the
device owner's listener is the same escalation. Refuse the mint server-side for a
secondary-org node, and drop a relay grant arriving on a secondary org's WS agent-side.

**Gate 4 delivery.** ⚠️ `docs/remote-config.md` opens with the measured consequence of
exactly this shape: *"the reason both features are still off nearly everywhere: the last
gate is the one nobody can reach."* An HQ relay is precisely a box an admin may not have
hands on. Decision: `relay_server_enabled` **stays device-local and unpushable**, and §12's
operator checklist carries the local-enable step. If that friction proves fatal in the
field, routing it through remote config requires `MANAGE_AGENTS` **and** `EXEC_DEVICE`
(`RELAY_DEVICE` once #888 lands) —
and the "survives a compromised server" claim for gate 4 must then be dropped rather than
kept as a property the delivery mechanism contradicts.

### 5. Port selection — **SETTLED by E2E-3: 3478**

**`relay_server_port = 3478`.** Field-measured 2026-08-28, not inferred. Geneve-shaped
64-byte frames (`Opt Len = 0`, pinned protocol `0x7788`, deliberately **not** STUN-shaped)
sent to a responder on mars:

| host | netcheck | **3478** | 11000 (coturn's relay band) | 41641 (high port) |
|---|---|---|---|---|
| **CORPLAP-3** — symmetric NAT, corp-managed, permanently on `relay:derp/tcp` | `relay band/udp: BLOCKED` | ✅ **PASS** | ❌ FAIL | ❌ FAIL |
| **CORPLAP-1** — Check Point corp, cone | band reachable | ✅ PASS | ✅ PASS | ✅ PASS |
| **CORPLAP-2** | `stun/udp: NO MAPPING` | ❌ FAIL | ❌ FAIL | ❌ FAIL |

Arrivals were confirmed at the responder, not merely inferred from a client timeout —
CORPLAP-3's frame landed from `192.164.201.1:10400`, matching the `MEASURED PATH` its own
`mh why` reports.

Three results, in order of consequence:

1. **3478 is the only port the motivating host can use.** `CORPLAP-3` reaches 3478 on an
   *arbitrary public IP* and **nothing else**. A relay on any other port cannot serve it.
2. **The STUN-ALG worry did not materialise** — a non-STUN-shaped payload passed on 3478.
   The test was still run Geneve-shaped, because a generic UDP echo would not have
   distinguished the two and the risk was real until measured.
3. **41641 is not a viable alternative**, so the high-port fallback is dead for this
   population.

⚠️ **This narrows the codebase's own claim.** `signaling.rs:5288` says a corp egress
*"whitelists STUN:3478 still drops the ~10-13k relay band"*. Measured, CORPLAP-3 drops **11000
and 41641** — it whitelists *only* 3478, so the constraint is "one allowed port", not "all
but the relay band".

**443/UDP** stays the documented fallback for hosts where 3478 is unavailable — which,
per the next warning, includes our own.

⚠️⚠️ **A relay host must be checked for DNAT, not just for a free socket — and `ss` will
lie to you.** The first probe of this matrix *failed* on 3478 and nearly produced the
opposite conclusion. The cause was not the corp egress: mars's `COTURN_DNAT` chain
redirects UDP/3478 on **both** public IPs to the coturn VM in `PREROUTING`, before any
local socket is consulted. `ss -ulnp` showed 3478 free, `HOST_FW_INPUT` showed it
ACCEPTed, and a bound listener still received nothing. The same chain consumes
**10000–13000** and **443 on `.74`**. Consequences:

✅ **The relay host is `scw-m2-asahi` (`62.210.194.66`)** — measured 2026-08-28, after mars
was ruled out below. It is a Scaleway Apple-M2 running Fedora Asahi: a public IP, UDP/3478
free, **no DNAT on it**, and firewalld the only gate. With 3478 opened, **`CORPLAP-3`
reached it** — arrival confirmed server-side from its own srflx `192.164.201.1:10400` — as
did `CORPLAP-1`. `CORPLAP-2` did not, as expected: it has no UDP anywhere.

⚠️ **The two home-LAN candidates were measured and REJECTED, not assumed.**
`MacBook-1` (`macbook-1-local-daemon`) and `neo16` share one consumer NAT behind
`37.63.112.129`. With a listener bound on the MacBook's `0.0.0.0:3478` and four datagrams
sent from mars to that public IP, the listener reported **`NO-INBOUND (timeout)`** — there
is no port forward, so neither can serve a relay to anyone off that LAN. Two traps caught
on the way, both of which would have produced a false answer:
`timeout` does not exist on macOS (the first listener never ran and its "33 bytes received"
was the shell's own error text), and a first probe was sent from `CORPLAP-2`, which has no
UDP at all and would have failed against a working host. A relay on a roaming laptop behind
a residential NAT is also the wrong shape regardless of reachability.

- **mars cannot host an org relay on 3478** without displacing coturn — the one port the
  target population can reach is already taken on the fleet's most natural relay host.
  E2E-1 must therefore either pick a host without coturn DNAT or move coturn first.
- This is the FR-4 class recurring: a host-level DNAT eating a port silently. Add a
  `iptables -t nat -S | grep <port>` check to the relay-host preflight, not just a bind
  attempt, and make the daemon **refuse to start the relay and log why** rather than
  binding a port it will never receive on.
- ⚠️ **40000 is likewise not testable on jupiter/zeus** — `coturn_dnat_rules[*].port_ranges`
  includes `"40000:49999"` on every meshharbor-hosting node. Use 41641 there.

**Reachability is new plumbing, not a generalised probe.** ⚠️ The first draft said the
existing `relay_band_udp` probe *"generalises"* and *"becomes a `CapVector` field"*. Both
halves are wrong:

- `probe_relay_band` (`netcheck.rs:144`) takes `alloc: &dyn RelayConn` — a **live coturn TURN
  allocation** — bootstraps permissions through it and reads the *allocation* for the echo.
  **Coturn is the responder.** An org relay must answer the probe itself; that is a new
  protocol, and it is why P1 ships a bind-only responder.
- `CapVector` (`netcheck.rs:60`) is four scalars in a **single process-global slot**
  (`:213`), shipped once per node. Reachability is a **pairwise (node × relay × port)** fact
  — an N×M table. It cannot be a `CapVector` field; it needs its own report
  (`rc:overlay.relay_probe`).

**SSRF.** ⚠️ Once the probe target becomes an operator- or server-supplied `SocketAddr`, an
oracle-returning internal port scanner exists: set a static endpoint to `169.254.169.254:80`
or an RFC1918 address and **every agent in the tenant — running as SYSTEM/root inside the
customer's corp LAN — probes it and reports reachability.** The countermeasure is already
written for this exact class: `validate_push_endpoint` (`crates/api/src/routes/push.rs:20`),
*"every resolved address must be globally routable (loopback / RFC1918 / 169.254 metadata /
CGNAT-and-overlay 100.64/10 / ULA / link-local v6 / v4-mapped forms all refused)"*. Validate
`endpoints` and `relay_static_endpoints` at approval time with that ruleset, re-check after
resolution, and constrain each node's probes to endpoints the server minted for **it**.

### 6. Carrier integration — a third `RelayKind`, **not** a fifth tier

⚠️ **This inverts the first draft's central design decision, and the inversion removes most
of the FR's implementation risk.** The first draft proposed a new `orgrelay` tier at BASE
230 between `srflx` (260) and `relay` (200), with a "rejected alternative" of folding it
into the relay tier. The rejection reason was: *"collapsing a 230-vs-200 preference into one
row makes `mh why` unable to answer 'why am I on DERP when there is a relay right
there'."*

**That reason describes the status quo the codebase already accepts.** `explain`
(`path.rs:917`) iterates `DIRECT_TIERS.chain(once(&DirectTier::Relay))`, and
`base(Relay) = B_RELAY` for **both TURN and DERP** — so `mh why` *already* cannot
distinguish a 52 ms coturn hop from a 175 ms DERP hop. That distinction has never lived in
the tier ladder; it lives in `PeerInfo.relay_kind` + `relay_transport`, rendered by
`relay_qualified_label` (`localclient.rs:1028`) as `relay:{kind}/{transport}`.

So the design is:

- **`RelayKind::Org`** joins `Turn` and `Derp` (`crates/tunnel-core/src/overlay/relay_link.rs:152`).
  `relay:org/udp` appears in the CONN column **for free** via `relay_transport_info`
  (`wg.rs:204`), with `relay_server()` supplying `relay_via`.
- **The transport is a fourth `RelayConn` impl.** `Carrier::Relay { conn: Arc<dyn RelayConn>, dst, dead }`
  (`wg.rs:155`) is already fully opaque to the send path, and `Carrier::send` (`wg.rs:410`)
  just calls `conn.send_to(buf, dst)`. DERP plugs in exactly this way — `impl RelayConn for
  DerpConn` (`transport/derp.rs:296`), `DerpMux::conn_for` (`derp.rs:458`) vending one per
  peer off a shared connection — and there are already **three** production impls
  (`DerpConn`, `TurnRelayConn` `transport/relay.rs:348`, `UdpRelayConn` `:491`). An org relay
  is a fourth, plus an `OrgRelayMux` shaped like `DerpMux`.
- **`relay_strategy` (`relay_link.rs:1016`) gains a branch**; the server verdict picks Org
  over Turn/Derp when a session exists.

⚠️ **What this avoids is the whole point.** The first draft's §9 named
`send_ip_packet` (`wg.rs:907`) as *"the send path that must learn 'via peer X'"*. It is not:
relay carriers already get a dedicated per-peer recv task (`wg.rs:1421`) and never touch the
carrier plane's shape demux. `send_ip_packet`, `send_to_peer`, `SendPeer` and the `Router`
need **zero changes**. The first draft also pointed the receive arm at
`CarrierPlane::route_by_index` (`carrier_plane.rs:738`) — which takes a WireGuard receiver
index *already extracted from a parsed WG packet* (its three callers are `handle_datagram`'s
arms at `:561-563`), so a Geneve frame can never reach it; and its `expected_src` contract
(`:766-800`) would trip the roam machinery on packets arriving from the relay's address.

A new tier would additionally have required navigating four hazards, three of them **silent**:

| hazard | anchor | why it fails silently |
|---|---|---|
| `is_direct()` = `!matches!(self, Relay)` | `lifecycle.rs:96` | a new variant reads as **direct** everywhere: `rx_stale_deadline` gives it the 60 s direct deadline (`:146`), `establish.rs:2596` makes **both ends initiate** the WG handshake, `:2562` books a direct-tier failure on demote-follow |
| `is_sticky` `_ =>` catch-all | `path.rs:825` | silently inherits LAN/public's 2-strike escalation |
| `suppression_half_life` `_ =>` catch-all | `path.rs:285` | same |
| `PathAction` / `Incumbent` | `path.rs:440`, `:428` | neither can represent an org relay; `decide` (`:1021`) iterates `DIRECT_TIERS` and its executor dials directly (`establish.rs:1312`, `:1400`, `:1472`) — an org relay needs a server mint plus an async 3-way bind, so `Install(OrgRelay)` would be handed to a direct-dial executor |

⚠️ **And one of the first draft's own "blockers" was a misreading, retracted here.** It
claimed the eligibility floor `base(tier) - penalty >= B_RELAY - ELIGIBILITY_EPS`
(`path.rs:850`) would leave a BASE-230 tier only **30 points** of penalty headroom against
srflx's 60. But the penalty is **scaled to each tier's own headroom** —
`weight(tier) = 2.0 * (base(tier) - B_RELAY)` (`path.rs:274-278`), whose doc states the
invariant: *"eligibility … is re-crossed after exactly one half-life."* Every tier is
suppressed for exactly one half-life; there is no asymmetry, and both "fixes" the first
draft proposed would have destroyed that invariant for every tier. The real constraint —
which stands, and is the reason to defer tier work at all — is that `weight()` is *derived
from* `base()`, so a new tier's base cannot be tuned independently of how aggressively it is
suppressed.

**Deferred, not abandoned:** if measurement later shows the selector genuinely mis-ranks an
org relay against TURN/DERP, the tier surgery above is the follow-up, opened with the field
evidence that justifies it.

### 7. Never self-wedge, never remove the floor

- **The floor is unconditional.** DERP registration is never torn down because a relay came
  up. `CORPLAP-2` must be measurably unaffected.
- **Never ratchet.** A pair on `relay:org` keeps re-attempting direct on the existing cadence.
- **The relay node protects itself.** `relay_max_sessions` (default **64**) and
  `relay_max_bitrate_per_session`; the relay's own carriers are exempt from its forwarding
  budget. An org must not be able to cost its HQ box its own remote access.
- **Failure is a downgrade, never a black hole**, convicted by `sweep_carrier_health`
  (`runtime/establish.rs:271`). ⚠️ FR-9's lesson: the dangerous bug was never "the carrier
  failed", it was *"both ends held a hold-down and went mutually deaf"* (#746).
- **Revocation is a push, not an expiry.** ⚠️ The first draft had no unmint at all, so
  flipping `peer_relay_mode` to `off` would have left live sessions forwarding indefinitely
  (§4: `idle_deadline` never fires under keepalive). `rc:relay.revoke{session_id}` fires on
  mode-off, ACL revoke, policy revoke and device removal — the shape `release_overlay_node`
  already uses, and `project_overlay_acl`'s recorded lesson that revocation **must** ship
  `removes`.
- **Privilege context.** ⚠️ `meshharbord` runs as **SYSTEM on Windows, root under systemd**.
  This FR puts a parser for attacker-controlled bytes, on an unauthenticated public UDP
  port, in that address space — alongside remote desktop, tunnels and SSH. Rust bounds
  memory safety, but a **panic on the receive path takes down the whole daemon**. So: the
  Geneve/bind parser must be total, proven by **fuzz/proptest over arbitrary byte strings**
  (not one table test), and the relay receive loop is wrapped in `catch_unwind` so a parser
  bug degrades the relay rather than the node. Compare rc.433's reasoning: *"A capability
  probe is untrusted third-party code by definition … and does not belong in the daemon's
  address space."*

### 8. Observability — shipped with its reader, per counter

⚠️ **The precedent:** FR-18's field log records `dropped_stale` *"could NOT be evaluated —
the counter was added without a reader"*. Still true: `stale_drops()`
(`transport/derp.rs:445`) has zero consumers in the tree.

| surface | addition |
|---|---|
| `mh peers` | `CONN` reads `relay:org/udp` — free via `relay_qualified_label` (`localclient.rs:1028`) |
| `mh peers --json` | `relay_kind: "org"`, `relay_via`, `relay_endpoint` (`PeerInfo`, `crates/localapi/src/lib.rs:393`) |
| `mh why <peer>` | the relay row names the kind; the tier ladder is unchanged (§6) |
| `mh netcheck` | relay node: `relay server: listening :3478, N sessions` |
| relay node | per-session `packets_rx`/`bytes_rx`, **one labelled counter per refusal reason** — bad MAC, unknown VNI, wrong tenant, at-capacity, expired, unbound-source — each with a `NodeStatus` reader. ⚠️ One counter for six causes cannot tell an attack from a misconfiguration during a flood |
| process-global | `ORG_RELAY_SESSIONS_OPENED_TOTAL` / `_CLOSED_TOTAL` only. ⚠️ **Not a gauge**: `evidence.rs:1-4` is *"cumulative since daemon start — consumers DIFF two readings, never judge absolutes"*. The live session count is a `NodeStatus` field |
| server | `peer_relay_audit` (90 d TTL) — every **approval**, mint and refusal, reason enumerated, written in one place via `decide() -> Result<Granted, DenyReason>`, read behind `VIEW_EXEC_AUDIT` (`VIEW_RELAY_AUDIT` after #888). **P3b:** `GET …/peer-relay-audit` (`?agent_id=`), one row shape for both actions (`action: approve \| mint`) so "who made this device a relay, and what went through it?" is one query on `agent_id`; `PeerRelayDenyReason` is the enumerated vocabulary (12 arms, wire-locked) |

⚠️ An empty `relay_via` is not evidence of "no relay available" — it may mean the node never
measured (`signaling.rs:1929`).
⚠️ `relay_via` must resolve from **the requesting tenant's own node row**. A multi-org
device has N per-tenant rows with independently-set names; resolving from any other would
leak tenant A's label for a shared device to tenant B, against `docs/multi-org.md:87-90`.

### 9. Where the code goes — implementation map

Verified against `origin/master`, 2026-08-28.

| change | file:line |
|---|---|
| Relay sub-kind gains `Org` | `crates/tunnel-core/src/overlay/relay_link.rs:152` `RelayKind` |
| **Transport: a 4th `RelayConn` impl + `OrgRelayMux`** | model on `transport/derp.rs:296` (`impl RelayConn for DerpConn`) and `derp.rs:458` (`conn_for`). **P4a:** `crates/tunnel-core/src/overlay/orgrelay/client.rs` — `bind` / `bind_any` (the member's half of §4; a Challenge is the success signal, the wire has no ack) + `OrgRelayConn: RelayConn` (8-byte header on send, only this session's frames from the relay's address on recv, synthetic peer addr, `close()` → dead latch). One socket per session rather than a mux: the relay binds a member by observed source, so each session needs its own source anyway |
| Client cascade branch | `relay_link.rs:1016` `relay_strategy` |
| Server verdict | `crates/api/src/ws/overlay.rs:1851` / `:1944` |
| Mint + ACL gate + rate limit | `overlay.rs:693` `handle_overlay_relay_request` (cross-tenant `:705-717`, ACL `:719-743`) — **P3c:** it now calls `crate::ws::org_relay::maybe_mint` beside the TURN grant |
| **The mint itself (P3c)** | `crates/api/src/ws/org_relay.rs` — `maybe_mint` (gate 1 + idempotency + audit), `plan_mint` (gates 2–5, candidate ranking by probe reports), `revoke_where` + the four trigger wrappers, `reconcile_acl` (on every policy refan), `handle_relay_probe`; `OrgRelayState` holds sessions / per-relay VNI cursors / the Lamport clock / join extras / probes, pod-local |
| Netmap shaping | `overlay.rs:1982` `shape_peer` |
| Wire model | `crates/remote_control/src/signaling.rs:3043` `NetmapPeer`; `:3021` `RelayStrategyWire` |
| Reachability report | new `rc:overlay.relay_probe`; **not** `CapVector` (`netcheck.rs:60`) |
| Carrier health / demotion | `crates/tunnel-core/src/overlay/runtime/establish.rs:271` `sweep_carrier_health` |
| Shape disjointness standard | `overlay/disco.rs:45-52`; `is_wg_shaped` `wg.rs:2413`; fix `payload_is_wg_or_disco` `remote_control/src/derp_frame.rs:39` |
| Anti-amplification standard | `overlay/disco.rs:69-70` (`FRAME_LEN = 85`) |
| Per-source limiter model | `overlay/carrier_plane.rs:705` `unknown_init_fresh`; `wg.rs:716-717` |
| SSRF validator to reuse | `crates/api/src/routes/push.rs:20` `validate_push_endpoint` |
| Permission bits + `ALL` bump | `crates/db/src/models/role.rs:104`, `:133` |
| CLI surfaces | `agents/meshharbor-cli/src/localclient.rs:1028` (`relay_qualified_label`), `:252` (`print_why`), `:141` (`netcheck`) |

**Config keys** — four wiring points each, per the contract at
`crates/agent-core/src/config_surface.rs:36-38`: field on `AgentConfig`; `const KEYS` entry
(`config_surface.rs:40`); getter + setter arms; and `env_bridge_bools` (`config.rs:2900`),
whose return type is `[(&'static str, Option<bool>); 54]` — **a fixed-size array whose
length must be bumped** — with `env_bridge_pairs_have_surface_parity` enforcing the pairing.

Keys: `relay_server_enabled`, `relay_server_port`, `relay_max_sessions`,
`relay_max_bitrate_per_session`, `relay_static_endpoints`. ⚠️ `peer_relay_mode` is **not**
one of them — it is gate 1, an `OverlayNetwork` field owned by the org. (The first draft
listed it in both places.) Model the boolean readers on the **opt-in** idiom
(`overlay/direct.rs:679`, `public_direct_enabled` — only `1|true|yes|on` enables), not the
default-on `crate::env::flag("…", true)` idiom; getting this backwards ships a relay that is
on by default.

**Docs that must change with P4**, because each states the cascade as a closed list:
`docs/overlay-communication.md`, `docs/overlay-nat-traversal.md`, `CLAUDE.md` (the cascade
appears in **two** places), and the customer-facing install docs (§12).

---

## Phases

| P | scope | kill switch |
|---|---|---|
| **P0** | **Wire forward-compatibility, rolled to the fleet before anything else** — `supports_org_relay` hello bit, `#[serde(other)]` on `RelayStrategyWire`, out-of-band session push (§3b). Nothing else lands until the fleet carries it. | decoder only |
| **P1** | **Bind-only responder** (bind + authenticated challenge, **forwards nothing**, no session table) + `rc:overlay.relay_probe` + `peer_relay_audit` + every counter **with its reader** | `relay_server_enabled=false` |
| **P2** | Forwarding: Geneve framing, VNI table, full 3-way bind, caps, revocation, `catch_unwind` | `relay_server_enabled=false` |
| **P3** | Server-side mint + gates + approval (`MANAGE_AGENTS`+`EXEC_DEVICE`, no free bit — §4) / audit behind `VIEW_EXEC_AUDIT` + rate limit + `peer_relay_mode`. Split: **P3a** models + wire (#890) · **P3b** DAO, routes, `peer_relay_audit`, fail-closed `try_load_acl` / `try_overlay_source_of`, limiter · **P3c** the mint | `peer_relay_mode=off` ⇒ zero mints |
| **P4** | `RelayKind::Org` live in the verdict + `relay_strategy` branch + promote/demote. Split: **P4a** the client in `tunnel-core` (`orgrelay/client.rs`: bind handshake + `OrgRelayConn`, proven over loopback against the real P2 relay) · **P4b** runtime + agent wiring — `RelayKind::Org`, the `relay_strategy` branch, `OverlayEvent::OrgRelay{Session,Revoke}`, relay-side `relay_serve` install, the probe report, the join flags — behind the config key · **P4c** the first field mint (`warn`, then `on`) — **field-verified 0.4.20** (CORPLAP-3↔mars on `relay:org/udp` via asahi; caps-probe fix #915 unblocked it) | `overlay_org_relay=false` |
| **P5** | jupiter/zeus provisioning in `~/k8s-cluster-multi` + weekly drift-audit cron | revert host_vars |
| **P6** | Admin UI: relay approval, org switch, audit section | UI-only |
| **Docs** | [`docs/peer-relays.md`](../peer-relays.md): what shipped, in the house style. ✅ Written 2026-09-24, **added retroactively** because this spec predates the docs-before-close rule | docs only |

⚠️ **P1 is NOT "inert by construction", and the first draft claimed it was.** The
reachability question cannot be answered by generalising the existing probe (§5) — coturn is
the responder today, and there is nothing on `mars:3478` to answer a generalised probe until
something is built. P1 therefore ships the smallest thing that can answer it, with a real
kill switch. That is what makes E2E-3 executable before P2.

---

## Acceptance criteria

⚠️ Where an instrument does not exist it is named as prerequisite work **in the same row**.

> **Test coverage map (2026-08-29).** The wire/mint hardening boxes ticked below are each backed by a named, non-vacuous test on master, not a field run:
> `tag₁`-refusal & same-egress third node → `orgrelay::bind::a_valid_cookie_without_the_member_secret_is_refused`; replay → `a_captured_exchange_does_not_replay_under_a_different_nonce`; amplification bound → `wire::probe_is_fixed_length_so_a_reply_can_never_amplify` + `every_control_kind_roundtrips_at_one_fixed_size`; bind flood → `server::a_bind_flood_is_rate_limited_before_it_can_cost_a_mac`; `policy_unreadable` & `rate_limited` mint refusals → `peer_relay_mint_tests::every_refusal_is_audited_with_its_reason`; fuzz/no-panic → `wire::control_and_data_decoders_never_panic_on_arbitrary_bytes`; shape disjointness over all 256 byte-0 values → `wire::shape_is_disjoint_from_wg_stun_and_disco_across_every_first_byte`; `relay_max_sessions` cap → `server::the_handle_cannot_push_the_table_past_its_cap`. Forward-only / drop-unbound-source → `server::three_sockets_relay_ciphertext_between_bound_members_and_nobody_else`; symmetric-NAT rebind → `session::an_authenticated_rebind_moves_the_address_and_an_unauthenticated_one_does_not`; lifetime/deadline bounds → `session::a_busy_session_still_ends_at_max_lifetime` + `an_idle_session_expires_and_is_reaped` + `a_session_nobody_binds_dies_at_the_bind_deadline`. Non-routable endpoint + approval authz were additionally field-verified (log below). **Still open** (no confirmable coverage from HEAD): the pre-FR-19 forward-compat box (needs the old `NetmapPeer` shape), and the field-instrument boxes (bytes-through-pod, port-audit scoping, 24 h socket census, kill-every-relay demote).

**P0 — wire compatibility (gates everything else)**

- [ ] A **pre-FR-19** agent receiving a netmap containing an unknown `relay_strategy` tag
      parses the frame and installs its peers. Asserted against the **old** `NetmapPeer`
      shape. *(Exposure closed at the source: the field-verified box “server never emits the new tag … lacks `supports_org_relay`” means a pre-FR-19 agent never receives it; the byte-level parser tolerance itself is unasserted — `RelayStrategyWire` has no `#[serde(other)]` — so this belt-and-suspenders box stays open, the exposure does not.)*
- [x] The server never emits the new tag to an agent whose hello lacks `supports_org_relay`. *(field 0.4.20: non-opted peers got `requester_unsupported`/`peer_unsupported`.)*

**Security (§4 — the half the first draft got wrong)**

- [x] A bind carrying a **valid cookie but no valid `tag₁`** is refused. *(This is the
      criterion the first draft could not have had: its handshake made any cookie-echoing
      party a legitimate binder.)*
- [x] A third node **on the same egress `addr:port` as a legitimate member** cannot bind or
      displace it — the same-NAT steal, i.e. the `CORPLAP-3` population.
- [x] A captured `Bind`/`Answer` pair **does not replay** in the next rotation window.
- [x] **`len(response) ≤ len(request)` on every bind-path reply**, asserted byte-for-byte.
- [x] A bind flood from N sources does not degrade the relay's **own** carriers, and the
      per-source limiter counts refusals by reason.
- [x] With `overlay_policies` **unreadable**, the mint is refused and audited with a distinct
      reason — the fail-closed property, which needs `try_load_acl` to be expressible at all.
      *(P3b: `try_load_acl(…, PolicyLoad::Always) -> Result` + `try_overlay_source_of`
      landed; `load_acl` / `overlay_source_of` keep their open posture as explicit wrappers
      that now LOG what they swallow. Integration test
      `try_load_acl_fails_closed_where_load_acl_fails_open` proves both postures on one
      unreadable row. **P3c:** the mint's `PolicyUnreadable` arm landed — an unreadable
      policy set, OR an unreadable member identity, OR an unreadable approved-relay list, is a
      refusal with that reason; `every_refusal_is_audited_with_its_reason` proves it on a
      malformed row over a real relay request.)*
- [x] Mint refused for a **secondary-org** node; a relay grant arriving on a secondary org's
      WS is dropped agent-side. *(P3c — server half: the join carries `org_primary`
      (additive, `#[serde(default)]`); the mint requires `Some(true)` on requester, peer AND
      relay, so an absent flag fails closed — tested for both `false` and absent. The
      agent-side drop is P4.)*
- [x] `mint_refused_for_non_routable_endpoint` — `169.254.169.254`, RFC1918, loopback,
      `100.64/10`, ULA, v4-mapped. *(P3c: the approval route refuses a non-public
      `static_endpoint` with 400, and the mint refuses `non_routable_endpoint` when one is
      smuggled past it (tested by writing the row directly); the address rule is the push
      SSRF validator's `is_global_unicast`, shared, not copied.)*
- [x] Mint refused when rate-limited, with the refusal audited. *(P3c: `rate_limited`,
      keyed (requester node, relay node) as §4 prescribes; the test pre-spends the ceiling
      in process. Deliberately AFTER relay selection so the row can name the relay the
      requester was hammering.)*
- [x] Relay approval requires `MANAGE_AGENTS` **and** `EXEC_DEVICE` (`RELAY_DEVICE` after
      #888), and writes an audit row — on BOTH arms. *(P3b: `decide_approval` is one pure
      function with 7 unit tests; the wiring is locked by the integration test
      `approval_needs_manage_agents_and_exec_device_and_audits_both_arms` — six attempts,
      six rows. Clearing an approval needs only `MANAGE_AGENTS`: revocation is not a grant.
      Field check against prod after the deploy.)*
- [x] The bind/Geneve parser survives **fuzzing over arbitrary byte strings** without panic.

**Correctness**

- [ ] With `peer_relay_mode=off` (the default): no `peer_relay_audit` rows, and on a fixed
      peer set the **selected carrier and every `TierWhy` row are unchanged** — diffed from
      `mh why --json` before and after. *(Now genuinely checkable because §6 adds no
      tier; the first draft asserted "byte-identical" while widening `[TierState; 3]`, so it
      would have failed its own first criterion.)* *(P3c: the zero-rows half is proven by
      `mode_off_writes_nothing_and_warn_audits_without_pushing` — under `off` the mint
      returns before any read past the cached mode; under `warn` it audits the would-be
      mint with `warn_only: true` and pushes nothing. The `mh why --json` diff is the
      P4 field check.)*
- [x] A relay forwards only between the two bound `addr:port`s for a VNI; a packet from an
      unbound source is dropped and counted by `ORG_RELAY_FORWARD_UNBOUND_SRC`.
- [x] **Shape disjointness over WG × STUN × disco × Geneve**, all 256 byte-0 values; a frame
      with `Opt Len ≠ 0` is rejected; `VNI = 0x2112A4` is never minted.
- [x] A **re-bind under a valid `tag₁` from a new source succeeds** (symmetric-NAT rebind)
      and **without one fails** — both directions. *(P2c proved both directions on the relay
      side; **P4a** proves the client's half of the success direction end to end —
      `a_member_rebinds_from_a_new_source_and_keeps_the_session` re-binds from a fresh socket
      with the same VNI + secret and the relay forwards to the new source.)*
- [x] A session exceeds neither `max_lifetime` nor the relay's own re-clamped deadlines when
      the server supplies longer ones.
- [x] `rc:relay.revoke` tears down a **live, traffic-carrying** session from all four
      triggers: mode-off, ACL revoke, policy revoke, device removal. *(P3c — the push half:
      `all_four_revocation_triggers_push_relay_revoke_to_every_party` mints, then fires each
      trigger in turn and asserts the revoke reaches the relay AND both members with the
      session's VNI, with a `revoke` audit row naming the trigger (`mode_off` /
      `acl_revoked` / `policy_revoked` / `device_removed`; a graceful leave adds
      `device_left`). "Traffic-carrying" is the P4 field half.)*

**The floor**

- [x] `CORPLAP-2` stays on `relay:derp/tcp` throughout, and org churn causes zero floor reconnects —
      *proven DEPLOY-FREE from pod logs (2026-08-30): a mint issues a per-peer DECISION — `org-relay: minted` for the one supported peer, log-only `mint refused reason=PeerUnsupported` for every floor node (no push, no reconnect); `CORPLAP-2`'s single 17 s WS blip was corp flakiness, non-coincident with any mint/revoke (9–11 min apart); `derp_registrations` steady at 12. The `NodeStatus` reconnect counter proved unnecessary. [#805 comment](https://github.com/jk-zhang-meta/MeshHarbor/issues/805#issuecomment-5471768287).*
- [x] Killing every relay mid-session demotes affected pairs within the carrier-health
      deadline. Asserted as a **positive signal** — both ends' demote timestamps inside the
      deadline, sampled from `peers --json` — not as an absence in a log tail.

**The win**

- [x] `CORPLAP-3` converges to `relay:org/udp` via mars, and `peers --json` shows
      `relay_kind:"org"` with `relay_via:"mars"`.
- [x] Same pair, same day, before/after: RTT ✓, overlay throughput ✓ (F2 = **3.18×**), and
      **SSH-over-overlay throughput** ✓ — *re-scoped from "RC `send_wait_max_ms`" (2026-08-30):
      RC media rides WebRTC (P2P/TURN), which the overlay org relay does **not** carry, so there
      was no carrier swap for RC to measure; SSH between two overlay nodes **does** ride the
      carrier (client → overlay TUN → WG → org/DERP/direct → target).* Fully measured 2026-09-01
      on 0.4.41 (same-session A/B, 25 MB `dd`, carrier-confirmed each run): **org `relay:org/udp`
      10.1–19.7 Mbps @ 86 ms** vs **DERP `relay:derp/tcp` 41.6 Mbps @ 50 ms** (direct 44.4).
      ⚠️ **The org relay is 2–4× SLOWER than the DERP floor for a single TCP stream** — the
      opposite of F2's raw-UDP result, and both are correct: the UDP blaster has no congestion
      control and measures raw forwarding capacity (org wins 3.18×), while SSH is one reliable
      TCP stream bounded by `window / RTT` and loss-sensitive, so org's extra hop (86 vs 50 ms,
      Asahi/FR while both members are AT/DE) costs it more than the capacity gains. **The org
      relay's value is pod offload (~74×) and raw headroom, NOT universal performance.**
      Follow-ups: relay PLACEMENT dominates this number (a relay near the members would likely
      flip it), and the org path deserves a loss/reordering check (the UDP arm was one-way and
      loss-blind by construction).
      [#805 comment](https://github.com/jk-zhang-meta/MeshHarbor/issues/805#issuecomment-5491431943).
- [x] DERP **bytes** through the `meshharbor2` pod fall measurably — *~74× for the measured pair on 0.4.23 (log below); metric shipped #952. Was: prerequisite:
      `derp_bytes_relayed_total` next to `DERP_REHOME_CLOSE_TOTAL` in
      `crates/api/src/cluster/metrics.rs`; only `derp_registrations` exists today.*
      ⚠️ `derp_registrations` itself must **not** fall — the floor is never torn down (§7).

**Operations**

- [x] `peer-relay-port-audit.sh check` fails on a host whose UDP port is closed, and the
      weekly cron files an issue. *(BOTH scripts delivered: `scripts/peer-relay-port-audit.sh` (`check` field-proven — exit 1 on a closed Asahi:3479, exit 4 on DNAT-stolen mars:3478) AND `scripts/peer-relay-port-audit-cron.sh`, a **mesh-native** wrapper (Fleet RPC, not ssh/scp). **LIVE ON mars 2026-08-31 (#1056):** the "unattended host" residual was a **MISDIAGNOSIS** — `mh exec` needs no user token (`mh exec --help`: the local daemon relays it over its own server connection; the server authorizes on the ORIGINATING device's permission). mars runs it via `MESHHARBOR_EXEC="sudo -n mh exec"` — its earlier `Permission denied` was only the CLI-as-gjovanov not reaching the root-owned LocalAPI socket. gjovanov crontab `45 4 * * 1` (30 min after the sibling mediasoup audit; gjovanov has passwordless sudo + gh + kubectl). Verified end-to-end from mars: Asahi:3478 → `AUDIT OK`/0; Asahi:3479 → `AUDIT FAILED` → `WOULD file GitHub issue`/1.)*
- [x] The port rule is **scoped**, not merely present. *(`scripts/peer-relay-port-audit.sh`, field 0.4.20: Asahi’s explicit `3478/udp` → scoped/exit 0; a blanket allow-all → exit 2; mars’s DNAT-consumed `3478` → exit 4.)*
- [x] A relay at `relay_max_sessions` refuses with a distinct reason; the pair falls back.
- [x] Relay-node UDP socket census flat over 24 h (F6). *(2026-09-24, closed by [FR-48](FR-48-meshharbord-ice-socket-leak.md) — this criterion is the consumer of that fix. The leak was never FR-19's: `turn::Client` has no `Drop`, so a **cancelled** TURN allocate stranded its underlay socket on every overlay node, relay or not; fixed in `agent-v0.4.100` (#1556). Hourly census over 24 h including the relay node `scw-m2-asahi`: no host ever exceeded 7 sockets, and the longest single lifetime — 20.0 h on 0.4.100 — ran **0.000/h** on all four, where 0.4.99 ran ~9/h. Full series and method in FR-48's field log.)*

**Documentation**

- [x] **Docs updated/created with diagrams, linked from `docs/README.md`** — [`docs/peer-relays.md`](../peer-relays.md): where the org relay sits in the ladder and why it is a `RelayKind` rather than a tier, the five gates and their owners, the mint and its audit vocabulary, the two-key bind, what the relay forwards and refuses, revocation, the floor, **what the relay operator can see** (§12a's table, published outside the spec as §12a asked), the measured results, the operating checklist and a code map. Three `mermaid` diagrams, `file:line` anchors verified against master; indexed in `docs/README.md`, and linked from `overlay-communication.md` UC-7 and `security-baseline.md`. ⚠️ **Added retroactively (2026-09-24)**: FR-19 opened on 2026-08-28, before the docs-before-close rule (#1401, 2026-09-05), and a close after that date binds it. Marked rather than backdated, so the spec does not claim it always complied.

---

## 10. Integration and E2E tests

### 10a. Unit (no MongoDB)

⚠️ `cargo test -p meshharbord --lib` **skips** the overlay tests; the lane needs
`--features overlay-l3`.

| test | asserts |
|---|---|
| `shape_disjoint_wg_stun_disco_geneve` | all 256 byte-0 values × the four shapes; `Opt Len ≠ 0` rejected. Model: `disco_shape_is_disjoint_from_wg_and_stun` |
| `geneve_header_roundtrip` | encode/decode, control bit, **u24** VNI, `0x2112A4` refused |
| `bind_requires_member_tag` | valid cookie + no `tag₁` ⇒ refused |
| `bind_refused_for_non_member_pubkey` / `..._cross_tenant_vni` | membership + tenant, relay-side |
| `bind_answer_does_not_replay_across_windows` | nonce defeats replay |
| `bind_reply_never_exceeds_request_bytes` | anti-amplification, byte-for-byte |
| `bind_mac_compare_is_constant_time` | `subtle`, so review catches a `==` |
| `rebind_requires_tag_and_keeps_vni` | both directions of the roam case |
| `bind_parser_never_panics` | **proptest/fuzz** over arbitrary bytes |
| `org_relay_wire_strings_are_locked` | `relay-server`, `relay_kind:"org"` |
| `relay_prefix_not_matched_by_equality` | the `ssh`/`ssh-consent` trap |
| `unknown_relay_strategy_tag_decodes_to_none` | §3b, against the **old** `NetmapPeer` shape |
| `no_relay_key_appears_in_desired_config` | ⚠️ asserts **no key matching `relay_*`**, so a future key is covered by construction — the first draft tested one key while the feature has five |
| `relay_kind_org_renders_as_relay_org_udp` | the CONN label comes free (§6) |

### 10b. Integration (`crates/tests`, real MongoDB + Redis)

New module `crates/tests/src/peer_relay_tests.rs`. Model on
`crates/tests/src/relay_region_tests.rs:46` (40 lines; `TestApp::spawn_with_settings`,
`fixtures/test_app.rs:179`, with both a REST and an in-process `app.state` assertion). For a
two-pod topology copy `cluster_tests.rs:798` via `spawn_pair` (`test_app.rs:152`).

Server-decision tests — all implementable as described: `mint_refused_when_mode_off`,
`mint_refused_without_relay_grant`, `mint_refused_cross_tenant` (404-shaped: leaks neither
content nor existence), `mint_refused_for_secondary_org`, `mint_requires_relay_server_cap`
(**412, never a hanging caller** — a caller that awaits must gate on the cap),
`mint_refused_when_rate_limited`, `mint_refused_for_non_routable_endpoint`,
`mint_is_idempotent_per_pair`, `approval_requires_relay_device_and_is_audited`,
`revoke_tears_down_live_session` (all four triggers), `audit_records_both_arms`.

⚠️ **The data-plane round trip does NOT go here.** The first draft proposed
`three_node_relay_roundtrip` in this crate with "A and B forced off direct". That is not
implementable: `crates/tests/Cargo.toml:17` depends on `meshharbord` with **default
features**, and `overlay-l3`/`overlay-netstack` are opt-in — **the overlay data plane,
WireGuard, carriers and `CarrierPlane` are not compiled into the test binary at all**
(`grep -l 'tunnel_core|overlay::' crates/tests/src/` returns nothing). `connect_agent`
(`agent_presence_tests.rs:57`) is control-plane only, and no "force off direct" primitive
exists anywhere. Put the round trip in a **`tunnel-core` in-crate test over three loopback
UDP sockets** — no TUN, no `CAP_NET_ADMIN`, which `ubuntu-latest` does not grant.

⚠️ CI: the lane's floor is `MIN=200` against ~294 (`integration-tests.yml:272`), so +11 tests
changes nothing detectable. **The real gap is the `pull_request: paths:` filter**, which
lists `crates/tests`, `crates/db`, `crates/services/src/dao`, `crates/api/src/routes`,
`crates/api/src/ws` and **not** `crates/tunnel-core/**` or `crates/remote_control/**` — so
every P2/P4 PR would skip this lane entirely. The workflow's own comment says to fix exactly
this: *"If a new crate becomes part of what these tests drive, add it here."* Add both paths
in the same PR as `peer_relay_tests.rs`.
⚠️ Set `RUST_LOG` — the harness installs a subscriber only when it is set
(`fixtures/test_app.rs:62`) — and use `--nocapture`.

### 10c. E2E on the real fleet — mars, zeus, jupiter

> ⚠️⚠️ **jupiter is storage-pinned production.** `k8s-worker-3` holds the node-local PVCs for
> `mongodb-0`, `minio-0` and `meshharbor2`; taking it down is a full meshharbor.itachi.fans outage, and this
> assumption caused a multi-hour one on 2026-07-19.
>
> ⚠️⚠️ **P5 and E2E-5 ARE disruptive to both cluster hosts, and an earlier draft denied it.**
> Playbook `11-host-networking` **flushes and rebuilds the COTURN chains** — the chains
> carrying the mediasoup RTC DNAT — and FR-4's field log records that a run *"demoted the
> fleet hosts' mesh carriers to DERP"*. So P5 on jupiter **is** a firewall flush of jupiter.
> Every playbook run is bracketed by `mediasoup-rtc-forwarding.sh check` **before and
> after**, in an announced window. E2E-5's hand-removal must name the exact chain and rule —
> a bare `iptables -D` in `COTURN_DNAT` renumbers the mediasoup rules.

| host | overlay | role | risk |
|---|---|---|---|
| **scw-m2-asahi** | 100.65.4.32 / `62.210.194.66` | ✅ **primary relay** — measured: 3478 free, no DNAT, and `CORPLAP-3` reaches it | **low** — hosted box, no prod pods, no coturn |
| **mars** | 100.65.4.14 | ❌ **cannot serve 3478** — `COTURN_DNAT` consumes it on both public IPs. Retained only as the Fleet-RPC driver and probe origin | low |
| **zeus** | 100.65.4.24 | second relay *only if a second is needed* | ⚠️ **high** — `k8s-worker-2` serves conference media for a hash-determined subset of **all** tenants (the FR-4 population). A COTURN flush is a media outage for that subset, and 3478 is DNAT'd there too |
| **jupiter** | 100.65.4.15 | third relay, ranking only | ⚠️ **high** — storage-pinned prod; same DNAT |
| ~~neo16~~, ~~MacBook-1~~ | 100.65.4.2 / .34 | ❌ **rejected by measurement** — one consumer NAT behind `37.63.112.129`, inbound UDP/3478 `NO-INBOUND` | n/a |

⚠️ **This table changed because of measurement, and it changes the plan.** The original
E2E-1 assumed mars as primary relay; mars cannot serve the only port the target population
can reach. `scw-m2-asahi` replaces it, which also removes the need to touch either
prod cluster host to run E2E-1 at all — the multi-relay ranking case is the *only* thing
that would need zeus or jupiter, and it is worth asking whether that case is worth a
COTURN flush on a host serving live conference media.

**E2E-1 — relay selection.** All three offered to `CORPLAP-3`; lowest measured RTT wins.
Then take mars's relay down and assert re-selection to zeus without a DERP round trip.
⚠️ **Not via `mh config set`.** The first draft claimed that was *"a config change, not
a service restart"* — false: `config_surface.rs:19` states *"Every key is read at daemon
startup, so the whole surface is `restart_required = true`"* (hardcoded `:596`, `:610`,
asserted by `every_key_gets_and_applies` `:1237`), and the CLI's live-apply allowlist is
exactly `exec_enabled | remote_config_enabled` (`localclient.rs:969`). A bound UDP socket
does not close on a TOML write, and restarting `meshharbord` on **mars** would kill the host
driving every `mh exec` in this plan. **Revoke server-side** (`Agent.peer_relay_policy`
→ `rc:relay.revoke`) — which also exercises §7's revocation path.

**E2E-2 — the floor holds.** `CORPLAP-2` still `relay:derp/tcp`, reconnects unchanged. The
regression test for the whole feature.

**E2E-3 — port matrix. ✅ RUN 2026-08-28 (§5); open decision #3 closed.** {3478, 443, **41641**} × {mars, zeus, jupiter} ×
{CORPLAP-3, CORPLAP-2, CORPLAP-1}. ⚠️ **Probe with Geneve-shaped payloads**, not a generic UDP
echo, or a STUN-ALG egress is measured wrong (§5). ⚠️ **41641, not 40000** — the latter is
DNAT'd on jupiter/zeus. Decides open decision #3.

**E2E-4 — kill switch.** `peer_relay_mode=off` ⇒ zero new mints immediately, **and** live
sessions revoked (§7), not merely left to a deadline that never fires.

**E2E-5 — provisioning drift.** Remove the zeus rule by hand (naming the chain), assert the
audit catches it, then assert Ansible restores it **from `host_vars`** — inside the
bracketed window above.

**E2E-6 — relay echo.** Extend `scripts/relay-pop/healthcheck.py`, which already does exactly
this for coturn PoPs: real data both ways *through* the relay, because a bound session that
forwards nothing looks healthy from the control plane. Non-zero exit on failure.

Driving is over Fleet RPC from mars (`docs/fleet-rpc.md:19`):

```bash
sudo mh exec <host> --timeout 45000 -- "mh netcheck"
sudo mh exec <host> --timeout 45000 -- "mh peers --json"
sudo mh diag pair mars CORPLAP-3
```

⚠️ Pass the whole chain as **one quoted arg** — the relay joins argv into a shell line.
⚠️ `mh exec` needs `exec_enabled` on the target; neo16 currently refuses.
⚠️ Use **`sudo`** on hosts running both daemon halves, or the per-user daemon answers and the
overlay looks empty.

**Soak** — model on `scripts/vpn-lab/run-lab.sh`. ⚠️ It measures **clock skew per run**
(`:44-64`) because CORPLAP-1 sat 21.4 s behind the dev box and manufactured an impossible
reading; a three-host relay comparison with a 30 s bind deadline needs that guard more, not
less.

### 10d. What CI can and cannot do

- `.github/workflows/integration-tests.yml` runs 10b — real coverage, once the paths filter
  is fixed.
- CI **cannot** cover 10c: no symmetric-NAT corp laptop, no blocked relay band, no three-host
  topology. *"Field-validated, not CI-validated… CI green ≠ done."*
- ⚠️ `--workspace` clippy compiles only `pub mod fixtures` from `crates/tests`, so
  `Checking meshharbor-tests` is **not** evidence the new tests build. `scripts/ci-local.sh`
  runs only `cargo check -p meshharbor-tests` (`:81`).

---

## 11. Field tests

Each must be shown to **fail (or be absent) on the current deploy first** — *"CI green is not
a result."*

| # | test | before (2026-08-28, 0.4.10) | after |
|---|---|---|---|
| F0 | **Rollout proof** — every host on the intended build | — | `readlink /proc/$(pgrep -x meshharbord)/exe` per host ⚠️ a `.deb` upgrade leaves `meshharbord` on the deleted inode and `--version` **lies**; `git merge-base --is-ancestor` before trusting the tag |
| F1 | `CORPLAP-3` carrier | `relay:derp/tcp`, 45 ms | `relay:org/udp` via mars |
| F2 | Throughput on that pair | **org 102.8 / DERP 32.3 Mbps delivered = 3.18×** (0.4.23, 2026-08-30) — org lossless at 102.8 (3 concurrent blasters); DERP saturated at 32.3 (29 % loss); org ceiling higher still | **≥3× MET (3.18×)** |
| F3 | **SSH-over-overlay throughput** (re-scoped from RC `send_wait_max`, 2026-08-30 — RC doesn't ride the overlay) | **org 10.1–19.7 @ 86 ms · DERP 41.6 @ 50 ms · direct 44.4** (0.4.41, 2026-09-01, same-session A/B) | ⚠️ **PREDICTION WRONG** — org is 2–4× SLOWER for a single TCP stream. Not a defect: TCP is RTT/loss-bound where the UDP blaster is not; org's win is pod offload, not universal speed. Relay PLACEMENT (FR relay, AT/DE members) dominates |
| F4 | `CORPLAP-2` carrier | `relay:derp/tcp`, 56 ms | **unchanged** |
| F5 | DERP bytes through `meshharbor2` | **5.99 MB** / blast (CORPLAP-3↔mars on DERP) | **81 KB** / same blast (on org) — **~74× lower**, = idle background |
| F6 | Relay-node CPU, RSS, **UDP socket count** on mars | *to record at P1* | within budget; **no socket growth** |

⚠️ **F6 is not padding.** On 2026-08-22 `meshharbord` held **15 446 UDP sockets after 12 h**,
exhausted the ephemeral range, and the host lost DNS entirely while `ping 1.1.1.1` stayed at
3 ms:

```bash
ss -uap | wc -l                                                              # Linux
netstat -ano -p UDP | awk '{print $NF}' | sort | uniq -c | sort -rn | head   # Windows
```

Results go in a `## Result — field-verified on <version>` comment with before/after tables,
the operator's words verbatim, the *unchanged* control number, and **dead hypotheses too**.

---

## 12. HQ deployment — the primary use case

An org runs one well-connected box at headquarters. Its remote and branch devices — hotel
Wi-Fi, CGNAT, symmetric-NAT corporate desktops — cannot reach each other directly and today
relay through meshharbor's DERP in Germany. Approved as an org relay, the HQ box means:

- **Content stays on the org's own hardware and in its own jurisdiction.** The relay cannot
  read it: it forwards WireGuard ciphertext keyed by VNI (§3a). WireGuard rekeys, so
  recorded ciphertext does not retroactively open on a later static-key compromise.
- **Capacity is the org's to size**, with no shared fate on the DERP path.
- **The path is usually shorter.**

### 12a. ⚠️ What the relay operator learns — state this to customers

The first draft said the relay is *"provably incapable of reading the traffic"* and stopped
there. That is true and incomplete, and the omission matters most in exactly this
deployment, where the relay is owned by an **employer's IT department** and the traffic is
often **an employee's remote-desktop session**.

| the relay **cannot** see | the relay **does** see |
|---|---|
| packet contents — pixels, keystrokes, files, SSH bytes | both parties' **WireGuard public keys** (handed over in the mint) |
| anything recoverable later from recorded ciphertext | both parties' **real `addr:port`** — a home IP, hotel Wi-Fi, mobile carrier NAT |
| | session start/stop and duration |
| | **per-side `packets_rx`/`bytes_rx`**, readable by whoever runs the host |

Remote-desktop traffic has a distinctive bitrate and packet-size profile, so per-side byte
counters at fine granularity reveal **when a person is at their machine and for how long**.
Moving the relay in-house therefore moves *content* into the customer's jurisdiction **and
newly exposes connection metadata about employees' personal networks to their employer.** A
relay operator can also selectively degrade one VNI.

Consequences taken here:

- Per-session byte counters on the relay default to **coarse aggregates**; fine-grained
  per-session counters sit behind an explicit config key.
- **The relayed endpoints get a gate of their own.** The four gates in §2 protect the
  relay's owner and the org; the two parties whose traffic is being steered had none — the
  inverse of how `exec_enabled` and `ssh_enabled` are argued. `overlay_org_relay=false` on a
  *client* is that node's last word, and it belongs in the gate table, not only in the
  phase plan.
- This table goes in the customer-facing docs, not just here.

**Operational checklist:** a reachable UDP port (§5), a static endpoint if behind NAT
(SSRF-validated), `MANAGE_AGENTS`+`EXEC_DEVICE` approval (`RELAY_DEVICE` after #888), an ACL grant naming permitted sources, and —
⚠️ because gate 4 is deliberately unpushable (§2) — **someone with local access to set
`relay_server_enabled` on the box itself.**

⚠️ If the HQ relay dies, affected pairs fall back to DERP — *degraded, not disconnected*. A
property to test (E2E-2, E2E-4), not to assert.

---

## Edge cases

- **Relay behind NAT.** Static endpoints cover the port-forwarded case; a relay that can be
  neither reached nor port-forwarded is **refused at approval time with a reason**, not
  offered and silently useless.
- **A relay that is itself relayed.** A node whose only carrier is DERP is never offered as
  a relay — guard on its measured caps, and **re-check**, since a node can fall to DERP
  after approval.
- **The relay restarts.** Sessions are lost and both peers re-mint. ⚠️ `lamport` is
  **server-owned** (§2), so a relay restart is purely a session-loss event and cannot
  invert ordering. (The first draft had the relay owning it, which contradicted §1.)
- **Corp VPN transitions.** A Check Point-class client kills *fresh* UDP while grandfathering
  existing flows (`docs/overlay-warm-relay.md`). A session established before VPN-up may
  survive; one attempted after will not. Interacts with the C4 warm-relay design — **do not
  solve both here.**
- **MTU — not a risk, and the first draft overstated it.** The overlay MTU is a fixed 1280
  (`agents/meshharbord/src/overlay.rs:41`), so worst case on the wire is
  1280 + 32 (WG) + 8 (Geneve) + 8 (UDP) + 20 (IPv4) = **1348**, comfortably under 1500.
  Geneve's 8 bytes is +4 over TURN's ChannelData and costs nothing against DERP (WS over
  TCP). Re-check only if the overlay MTU is ever raised. ⚠️ And do **not** cite
  `mh diagnose` as the path-MTU instrument — it is
  `bail!("T3: diagnose not yet wired")` (`agents/meshharbor-cli/src/cli.rs:637`); only its
  doc comment describes the probe.

---

## Out of scope

- Sharing UDP/3478 with a co-resident coturn (mars). Pick another port; revisit only if
  E2E-3 says 3478 is the sole port that works there.
- Relaying for other tenants (a public or paid relay marketplace). ⚠️ Note this is only out
  of *scope*, not out of *reach*, unless §4's authenticated bind holds — an attacker who
  could bind both sides of a VNI would have a UDP proxy that rewrites the source to the
  org's HQ IP. Not a pivot into the org's network (the MAC covers `addr:port`), but IP
  laundering ending in blocklisting of the customer's address. The invariant, with a test:
  the relay forwards **only** between two addresses bound under valid member secrets, for a
  session it was minted, and never answers a packet it cannot attribute to a live session.
- Relay chaining (A → R1 → R2 → B).
- TCP or TLS org relays. If UDP is dead the DERP floor is the answer.
- Wire compatibility with Tailscale.
- Making the DERP floor optional.
- A new carrier **tier** (§6) — deferred pending evidence the selector mis-ranks.

---

## Open decisions

1. **Where the mint lives** — the API (consistent with "the server verdict decides") or the
   relay node against a server-signed token (fewer round trips, survives a control-plane
   blip). Leaning API for P3.
2. ~~**Default port: 3478 vs 443**~~ — **CLOSED 2026-08-28 by E2E-3: 3478** (§5). The
   motivating host reaches 3478 on an arbitrary public IP and no other port tested. Newly
   opened by the same run, and now the harder question: **which host can actually serve
   it**, given mars's `COTURN_DNAT` already consumes 3478 on both its public IPs.
3. Does a relay **advertise capacity** for server-side load-balancing, or simply refuse at
   the cap? Refusal is simpler; advertisement is better for an HQ node serving many devices.
4. **Per-session byte-counter granularity** (§12a) — coarse by default is taken; is
   fine-grained worth offering at all, given what it reveals?
5. Whether `relay_server_enabled` should ever become remotely settable (§2, gate 4), and if
   so what happens to the "survives a compromised server" claim.

---

## Field-verification log

| date | build | result |
|---|---|---|
| 2026-08-28 | 0.4.10 | **Pre-implementation evidence sweep.** Fleet-wide `netcheck` + `peers` + `why` from mars over Fleet RPC. 3/12 online peers on `relay:derp/tcp`, **all TCP**. `relay band/udp` **BLOCKED** on `CORPLAP-3` (symmetric NAT), jupiter and zeus; `stun/udp: NO MAPPING` on `CORPLAP-2` (whose relay-band cell is **derived, not probed**). Live tier ladder captured for `100.65.4.30`. ⇒ cluster-host firewall provisioning promoted to its own phase (P5); default port set to **3478 as a hypothesis**, with E2E-3 to settle it. ⚠️ Also found while specifying: `blocked_by: "peer-relays-instead"` (`path.rs:590`) already uses "peer relay" for nearly the opposite thing — the product keeps the industry term, the wire uses `relay_kind:"org"`. |
| 2026-08-28 | — | **Independent review, three lenses, before publication.** Three material corrections, each retained inline as a warning rather than silently fixed: (1) **§6 inverted** — a fifth carrier tier was the wrong design; `RelayKind::Org` plus a fourth `RelayConn` impl needs zero changes to `send_ip_packet`/`SendPeer`/`Router`/`CarrierPlane`, and avoids four hazards in `path.rs`/`lifecycle.rs`, three of them silent. The first draft's own "30 points of headroom" blocker was a **misreading** of `weight() = 2×(base − B_RELAY)` and is retracted. (2) **§4 was insecure** — the bind proved return-routability only; it now carries a per-member `bind_secret` delivered over the authenticated control WS, plus nonce, domain separation, constant-time compare and anti-amplification padding. (3) **§2b overread its instrument** — `relay_band_udp` probes coturn's ~10–13k band and never touches 40000, so the port choice is a hypothesis for E2E-3, which must additionally use Geneve-shaped payloads because a STUN ALG on 3478 may pass STUN and drop us. Also corrected: gate 2 is inert (`OverlayAclMode` defaults `Off`), "fail closed" is unreachable through `load_acl`'s `AclCtx` return, VNI scoping was self-contradictory, P1 was not inert, `mh config set` is not live outside a two-key allowlist, `three_node_relay_roundtrip` was not implementable (overlay isn't compiled into `crates/tests`), and several acceptance criteria named instruments that do not exist. |
| 2026-08-28 | 0.4.11 | **E2E-3 RUN — open decision #3 CLOSED: the default port is 3478.** Geneve-shaped 64-byte frames (`Opt Len 0`, pinned proto `0x7788`, deliberately not STUN-shaped) from three clients to a non-amplifying responder on mars; arrivals verified server-side, not inferred from client timeouts. **CORPLAP-3 — symmetric NAT, corp-managed, the host this FR exists for — reached 3478 and NOTHING else** (11000 ✗, 41641 ✗); CORPLAP-1 reached all three; CORPLAP-2 reached none, confirming the DERP floor. ⇒ 3478 confirmed, 41641 dead as a fallback, 443 retained only as a documented alternative. Two corrections fell out: the codebase's *"drops the ~10-13k relay band"* is **narrower than measured** (CORPLAP-3 allows *only* 3478, not "all but the band"), and the STUN-ALG risk §5 flagged **did not materialise**. ⚠️ The run's first probe FAILED on 3478 and nearly produced the opposite conclusion — the cause was mars's own `COTURN_DNAT` redirecting udp/3478 on both public IPs in `PREROUTING`, invisible to `ss -ulnp` and downstream of an ACCEPTing `HOST_FW_INPUT`. Isolated by a STUN-shaped control (also blocked ⇒ not payload inspection), then by reading the nat table. **mars therefore cannot host an org relay on 3478 without displacing coturn** — a new open question for E2E-1. Test rig fully torn down and verified: DNAT restored, temp accepts removed, nothing bound, mesh carriers unchanged. |
| 2026-08-28 | 0.4.11 | **Relay-host question ANSWERED: `scw-m2-asahi` (`62.210.194.66`).** mars was ruled out by its own `COTURN_DNAT`, so three further candidates were measured rather than argued about. **Asahi (Scaleway M2 / Fedora Asahi): public IP, 3478 free, no DNAT, firewalld the only gate — with 3478 opened, `CORPLAP-3` reached it** (arrival confirmed server-side from its srflx `192.164.201.1:10400`), as did `CORPLAP-1`; `CORPLAP-2` did not, consistent with having no UDP at all. **`MacBook-1` and `neo16` REJECTED**: they share one consumer NAT behind `37.63.112.129`, and a listener on the MacBook's `0.0.0.0:3478` reported `NO-INBOUND (timeout)` against four datagrams from mars ⇒ no port forward, so neither can serve anyone off that LAN. ⚠️ Two traps caught on the way, each of which would have produced a false answer: `timeout` does not exist on macOS, so the first listener never ran and its "33 bytes received" was the shell's own error text; and the first inbound probe was sent from `CORPLAP-2`, which has no UDP and would have failed against a *working* host. ⇒ E2E-1 is re-planned around Asahi, which also removes any need to touch a prod cluster host to run it. Rig fully torn down: responder stopped, firewalld port removed (`ports:` empty again), scratch files deleted, service list unchanged. |
| 2026-08-29 | 0.4.15 | **P1 FIELD-VERIFIED — the real daemon serves probes on `scw-m2-asahi:3478`.** P1a–P1d shipped (#816, #826, #832, #852), deployed to Asahi, `relay_server_enabled=true`, firewalld `3478/udp` permanent. The daemon logs `org-relay probe responder listening … local=Some(0.0.0.0:3478)` and holds the socket. Against the **real responder** (not the Python stand-in): **`CORPLAP-3` PASS ×2** — the corp-managed symmetric-NAT host this FR exists for — and **`CORPLAP-1` PASS**; `CORPLAP-2` fails, as it must, having no UDP anywhere. ⚠️ **Deploying a non-release build is not possible on a host with an active updater**: a hand-installed 0.4.14 was silently overwritten **90 s later** by the published 0.4.15 (`post-install watcher … expected=agent-v0.4.15`). The first diagnosis — "my rollback timer fired" — was **wrong**; `journalctl -u fr19-rollback.service` said *No entries*, and the agent's own log named the updater. The fix was to stop fighting it rather than disable `auto_update` on a fleet host: master was already 0.4.15 **and** carried P1d while the *released* 0.4.15 tag predated the merge, so a master build reports a version the updater does not consider newer. ⚠️ **A mid-test FAIL on `CORPLAP-1` was the CLIENT, not the relay** — its own netcheck flipped to `stun/udp: NO MAPPING` / `nat: untyped` when its Check Point VPN came up, and flipped back to `ok`/`cone` when it dropped, with the probe passing again on the same relay. VPN-up ⇒ fail, VPN-down ⇒ pass, same host: the client's capability vector is what settles "the relay broke", not the server. ⚠️ Observability gap found in use: the Rust responder only aggregates counters every 300 s **and sleeps before its first report**, so there is a 5-minute blind window at startup and no per-datagram arrival evidence — the stand-in logged every packet, which is what made the earlier DNAT confound visible. Worth a `NodeStatus` field before P2. |
| 2026-08-29 | — | **P2a–P2c implemented; the relay forwards on loopback.** P2a (#881, merged): the authenticated bind — two keys with two jobs, fixed-width domain-separated MACs, constant-time compare via `subtle` added as a real dependency; deleting the `tag₁` check (the first draft's design) fails four of eleven tests. P2b (#885): the session table — forward only between the two bound addresses (mutation-verified), `max_lifetime` because `idle_deadline` never fires under a 25 s keepalive (100 keepalive-spaced datagrams prove it), authenticated re-bind in both directions, revoke kills a live session at once, a 64-session cap that refuses rather than grows. P2c: `RelayServer` on one socket — probes, bind, forwarding — with `catch_unwind` **verified by a test-induced panic** (one datagram lost, counter incremented, relay still answers), a per-source limiter that runs *before* the MAC (mutation-verified: disabling it lets all 50 bad binds reach the MAC), and the spec's `three_node_relay_roundtrip` over **three loopback UDP sockets**: A↔B relay, an intruder on the known VNI dropped and counted by the open-proxy tripwire, revoke stops forwarding, and the relay still echoes a probe afterwards. ⚠️ **Design correction found by writing the loopback test**: P2a's `tag₁` covered the observed source address, which a NAT'd client cannot know on its first packet — the handshake was unimplementable for its own target population. Address is now bound at step 3 via the cookie, as in the reference design (§4). ⚠️ `#881`'s commit staged only `crates/tunnel-core` and left the one-line `Cargo.lock` update behind; CI did not notice because no Rust lane builds `--locked`. Committed in P2b. **Not field-verified**: no deploy yet — a P2c build on Asahi holds no sessions until P3 mints them, so it behaves exactly as P1. |
| 2026-08-29 | 0.4.17/0.4.18 (server: #899 deploying) | **P4c BASELINE, taken before any relay exists.** From `CORPLAP-3` (`mh peers` over Fleet RPC): EVERY online peer is `relay:derp/tcp` — mars 49 ms, jupiter 45, zeus 46, **scw-m2-asahi 67**, CORPLAP-1 88, CORPLAP-2 100, regal 129, rozalina 164, MacBook 202; neo16 `upgrading`. The whole of CORPLAP-3's mesh traffic crosses the API pod today — the population §2 describes, exactly. Server side: primary tenant `100.65.4.0/22`, `acl_mode` and `peer_relay_mode` unset (off), **0 overlay policies**, no relay approved, nobody advertising `relay-server` (P3a's verb is not in a release yet). Asahi: `/etc/meshharbor/config.toml` has `relay_server_enabled = true` (from P1), `auto_update = true`, public NIC `62.210.194.66` — so the 0.4.19 release makes it a serving relay on arrival, and the mint will pair that address with 3478. ⚠️ Two exec traps on the way: on a Windows target the Fleet-RPC shell runs as SYSTEM with no `mh` on PATH — locate `C:\Program Files\MeshHarbor\meshharbord.exe` and run `cli peers`; and `mh config` has `ls`/`set`/`clear`, no `get` — read `/etc/meshharbor/config.toml` on Linux. |
| 2026-08-29 | 0.4.19 (Asahi, CORPLAP-3, mars all on it) | **P4c step 1 found a real defect on the first host: `relay-server` was never advertised.** Asahi on 0.4.19 with `relay_server_enabled = true`: `mh status` reads `org relay 0.0.0.0:3478 — bound`, yet `agents.capabilities.rpc` lacks `relay-server`, so the mint's relay-candidate step could only ever answer `no_relay`. Cause: the hello's capability list is computed in the caps-probe CHILD (rc.433), which inherits the environment but NOT the process-local S2 config-fallback registry, so `relay_server_enabled()` read its built-in default there. Proven on the host: `sudo env MESHHARBORD_RELAY_SERVER_ENABLED=1 MESHHARBORD_CAPS_CHILD=1 meshharbord caps-probe` prints the verb, the bare probe prints nothing. Fix in 0.4.20: the parent exports every registered knob to the child as a real `MESHHARBORD_*` env var (`config_fallbacks_for_child`, precedence preserved) AND recomputes `caps.rpc` itself, so a config-derived verb never depends on what the child saw. The relay had been serving the whole time; the fleet could not be told. Baseline for the fix: the `mint` audit has zero rows and CORPLAP-3's `peers` still reads `relay:derp/tcp` for every peer. |
| 2026-08-29 | **0.4.20** (fleet) | **P4c COMPLETE — org relay carried real traffic and was revoked.** After #915 shipped, all three hosts advertised `relay-server`. `peer_relay_mode` off→warn→on, Asahi approved (`serve:true`) + one ACL rule granting the relay node. On `warn`, mint rows for CORPLAP-3↔mars carried `warn_only:true`; every non-opted pair `requester_unsupported`/`peer_unsupported`; a secondary-org node `secondary_org`. On `on`, the fourth ladder-climb window (vni=6/gen=6) caught a clean dual-bind and the carrier **flipped both directions to `relay:org/udp` ~84 ms** (`CORPLAP-3 why mars` = `carrier relay:org via 127.0.0.6`), Asahi `forwarded=128 bound=4 drop_bad_cookie=0`, sockets 36→18 (no leak). A dual-ended tcpdump caught the shaped-probe→challenge→bind on Asahi:3478 from both members. `PUT …/peer-relay-policy {serve:false}` tore the live session down → both ends back to `relay:derp/tcp` in ~20 s + `revoke` audit row; `mode:off` returned `relays:[]`. Floor control **CORPLAP-2** and every non-opted peer stayed `relay:derp/tcp` throughout — only the approved pair moved; never self-wedged. ⚠️ Org relay engages on a **ladder climb, not on the mode flip**: vni 4–5 minted but idle-reaped before both members bound (the reap is the make-before-break floor working), and a pair parked on a healthy DERP floor won't re-request until it churns — restart a member to provoke it. Tenant left at `mode:off`. |
| 2026-08-29 | **0.4.20** (live route) | **P4d — non-routable static endpoint REJECTED on the live route (SSRF/port-scan guard).** `PUT …/agent/{asahi}/peer-relay-policy` with `static_endpoints=[…]` returned `400 bad_request "… is not a public ip:port"` for `169.254.169.254:3478` (cloud metadata), `10.0.0.5`/`192.168.1.1` (RFC1918), `127.0.0.1` + `[::1]` (loopback), `100.64.0.1` (CGNAT/overlay), and `1.2.3.4:0` (port 0); a globally-routable `8.8.8.8:3478` was ACCEPTED (200). Matches the unit test `a_non_routable_static_endpoint_is_an_error_not_a_skip`. Reverted to `serve:false`; tenant stayed `mode:off`. |
| 2026-08-29 | **0.4.20** | **P4d — approval authz confirmed.** The live route runs `decide_approval` (my Owner session approves via the `ADMINISTRATOR` bypass; a `serve:false` clear and a `serve:true` approve each wrote a `peer_relay_audit` row, observed in the field). The permission split is locked by five unit tests: `an_admin_without_exec_device_cannot_approve`, `an_admin_with_exec_device_can_approve`, `a_member_is_not_a_device_admin_even_to_clear`, `exec_device_alone_is_not_a_device_admin`, `administrator_bypasses_as_everywhere_else`. |
| 2026-08-29 | **0.4.20** (fleet, disruptive test authorized by operator) | **Kill-every-relay demote + relentless re-upgrade (box “killing every relay mid-session demotes…”).** With CORPLAP-3↔mars live on `relay:org/udp` (~85 ms) via scw-m2-asahi, the relay daemon was hard-killed (`pkill -9`, `KILL@20:19:19Z`). CORPLAP-3’s carrier read `blocked` by **20:19:33Z (+14 s)** and fully demoted to `relay:derp/tcp` by **20:19:45Z (+26 s)** — inside the carrier-health window — staying connected the whole time (never self-wedged). The relay was restored at `RESTART@20:21:19Z`; on the next member ladder-climb CORPLAP-3↔mars **re-upgraded to `relay:org/udp`** (81–85 ms) — the never-ratchet / relentless-re-upgrade commitment. Floor control **CORPLAP-2** stayed `relay:derp/tcp` throughout. |
| 2026-08-29 | **0.4.20** | **RTT before/after (partial for box “same pair before/after”).** Same CORPLAP-3↔mars pair: `relay:org/udp` **81–86 ms** vs `relay:derp/tcp` **48–66 ms** — the org relay is *higher* RTT here because scw-m2-asahi (Scaleway/FR) adds a hop the cluster-hosted DERP does not. Expected, and the point: an org relay trades a little latency to keep the pair off the API pod (control-plane-as-data-path). The metric that captures the win is DERP-bytes-through-`meshharbor2` (box below), which needs a pod byte counter and is unmeasured; throughput / RC `send_wait_max` not captured, so that box stays open. |
| 2026-08-29 | **0.4.20** | **Operational note from the kill test: `systemctl start` on an ORPHAN-daemon host starts a restart storm.** Asahi’s daemon was an unmanaged orphan (the 0.4.20 updater self-relaunched as `meshharbord run`, leaving `meshharbord.service` inactive). The kill-test’s `systemctl start meshharbord` recovery brought the service up beside the surviving orphan, and `Restart=always` then looped it against the singleton config-lock (`“Another meshharbord is already running… exiting”`, NRestarts=32) — `is-active` reads `activating`/`auto-restart` while the real daemon is perfectly healthy. Cleaned to a single service-managed daemon (`stop` → `pkill -9` → `start`); Asahi ended **better** than found (managed + auto-recovering, NRestarts=0). ⚠️ Recover an orphan host by killing the orphan FIRST, then `systemctl start` — never `start` beside it. |
| 2026-08-29 | **0.4.20** | **`scripts/peer-relay-port-audit.sh` delivered + field-tested (boxes “port-audit check” / “scoped, not merely present”).** A relay-host firewall drift guard (firewalld / nftables / iptables) that asserts the UDP relay port is admitted by a rule that NAMES the port (scoped) and is not stolen by a DNAT. Field results: **Asahi** (firewalld) `3478` → scoped, exit 0; a closed `3479` → exit 1 (the drift signal, proven non-destructively rather than by removing Asahi’s real rule). **mars** (nft) `3478` → exit 4 — it machine-detects the `dnat to 10.10.10.11:3478` that steals the port upstream of the socket, i.e. WHY a cluster node cannot host a relay on 3478 even though the filter accepts it (the §5 line-565 hint). Two real bugs were caught and fixed during the field test: grep’s `[^
]` means “not backslash-or-n” (broke matching on any rule containing “cou**n**ter”) — use `.*`; and a filter-accept audit alone gives a false PASS on a DNAT host, so the DNAT-conflict check is load-bearing. ⚠️ Still to wire: the weekly build-host cron that pushes it over the mesh and files a GitHub issue on non-zero, and the fire-on-zeus proof. |
| 2026-08-30 | **0.4.23** (server; metric #952) | **THE POD-OFFLOAD MEASURED — box “DERP bytes through `meshharbor2` fall”.** Shipped `derp_bytes_relayed_total` (an `AtomicU64` in `cluster/metrics.rs`, incremented in `derp::forward_frame` ONLY on a successful enqueue, exported at `GET /api/cluster/status`), deployed to prod (`v20260829-ebbafd735cf4`, both pods), canary-confirmed the field is present. A/B on the primary tenant’s affinity pod (10.10.20.11): an identical 12.5 MB one-way UDP blast (mars → CORPLAP-3’s overlay IP @ 5 Mbit/s × 20 s; no CORPLAP-3 listener needed — the WG ciphertext still crosses the carrier). **CORPLAP-3↔mars on `relay:derp/tcp`** → pod delta **5,989,351 B (~6 MB)**; **same pair on `relay:org/udp`** (via scw-m2-asahi) → pod delta **81,193 B (~79 KB)** = the measured idle background (3 KB/s). **~74× reduction** — the org relay carried the pair’s traffic CORPLAP-3→asahi→mars, off the API pod entirely, which is the whole point of the FR. ⚠️ `derp_registrations` stayed **12** in both states — the floor is never torn down (the invariant the box demands). ⚠️ The ~6 MB vs 12.5 MB sent is loss-tolerant DERP drops to CORPLAP-3’s slow corp-Windows WS consumer, correctly UNCOUNTED (the metric increments only on a successful `try_send`). RTT note (box “same pair before/after”): org **85 ms** vs DERP **47 ms** — org is HIGHER (asahi/FR adds a hop); latency is the trade, pod-offload is the win. |
| 2026-08-30 | **0.4.23** | **THROUGHPUT before/after on the same pair — box "same pair before/after" (throughput leg).** Same CORPLAP-3↔mars pair, same 1000 B UDP blaster (CORPLAP-3→mars overlay IP, PowerShell `UdpClient`); mars a python3 sink counting *delivered* bytes over a 10 s steady-state window; provoked onto `relay:org/udp` by a member restart, then revoked back. **DERP floor:** offered 45.4 → **delivered 32.3 Mbps (~29 % loss)**. **Org relay (`scw-m2-asahi`):** offered 42.3 → **delivered 44.5 Mbps (~0 % loss)**. Org carried the *whole* offered load losslessly where DERP dropped ~29 % (single-flow TCP-relay HOL through the pod), so org's true ceiling is ≥44.5 Mbps — the run is **send-capped by PowerShell (~45 Mbps)**, not by the relay. Offload cross-check on the same blasts: **73 KB** through the pod on the org leg vs tens of MB on DERP (re-confirms ~74×). `derp_registrations` stayed **12**; the mode-off revoke returned the pair to `relay:derp/tcp` (46 ms). ⚠️ The ≥3× *target* is not a hard-proven multiple (blaster send-capped below org's ceiling); org is shown strictly better (lossless vs 29 % loss). ⚠️ RC `send_wait_max_ms` leg still open (needs a browser RC session). [#805 comment](https://github.com/jk-zhang-meta/MeshHarbor/issues/805#issuecomment-5465358076). |
| 2026-08-30 | **0.4.23** | **≥3× THROUGHPUT — HARD NUMBER (box "same pair before/after", throughput leg).** Follow-up to the send-capped row above: **3 concurrent** `UdpClient` blasters on CORPLAP-3 (`Start-Job`×3) push past the single-loop ~45 Mbps cap. Same CORPLAP-3↔mars pair on `relay:org/udp` (Asahi), same mars python3 sink, 10 s steady window: offered **104.3** → **delivered 102.8 Mbps @ ~0 % loss**. Against the DERP floor's established **32.3 Mbps** ceiling (saturated — 29 % loss already at 45 offered, so offering more only drops more): **102.8 / 32.3 = 3.18×**, still lossless so org's true ceiling is higher (now CORPLAP-3-uplink bound, not relay bound). ✅ **F2 ≥3× MET.** Carriers confirmed on both legs; symmetric-NAT CORPLAP-3 climbs on a member restart, `mode:off` revokes. ⚠️ RC `send_wait_max_ms` is MIS-SCOPED for an org-vs-DERP A/B (RC media rides WebRTC/TURN, NOT the overlay relay — no carrier swap to measure); needs a scope decision, not a measurement. [#805 comment](https://github.com/jk-zhang-meta/MeshHarbor/issues/805#issuecomment-5471722265). |
| 2026-08-30 | **0.4.33/34** | **F3 RE-SCOPED to SSH-over-overlay + measured (was RC `send_wait_max`).** RC media rides WebRTC/TURN, which the overlay org relay does NOT carry — no carrier swap to measure; SSH between two overlay nodes DOES ride the carrier, so F3 now measures SSH throughput. SSH `CORPLAP-3`→mars (mars sshd :22 reached over the overlay, ephemeral key, 60 MB `dd`→.NET FileStream, `Compression=no`): **DERP `relay:derp/tcp` = 58.9 Mbps** (stable, carrier-confirmed) vs **direct = 44.4 Mbps** — for this symmetric-NAT corp host DERP BEATS its own flaky direct, and SSH-over-DERP 58.9 > the raw-UDP DERP 32.3 because SSH is a reliable TCP stream (flow-controls, doesn't overrun the buffer). **Org SSH leg pending** — the host would not re-request the org climb (all server gates ready: `mode:on`, Asahi `serving:true`, but no `OverlayRelayRequest` — a re-request backoff after ~2 h of enable/disable churn; a silent-loss induced block just left it `upgrading`, not relay-locked). Org's advantage on this exact pair is established via the **3.18× UDP result** above. [#805 comment](https://github.com/jk-zhang-meta/MeshHarbor/issues/805#issuecomment-5480692218). |
| 2026-09-01 | **0.4.41** | **F3 COMPLETE — the org SSH leg, and the prediction was WRONG (in the useful direction).** The member's re-request backoff had cleared, so the climb was provoked normally and held. Same-session A/B, same pair, same 25 MB `dd` over SSH, carrier confirmed each run: **org `relay:org/udp` 10.1 & 19.7 Mbps @ 86 ms** vs **DERP `relay:derp/tcp` 41.6 Mbps @ 50 ms** — the org relay is **2–4× SLOWER than the DERP floor for a single TCP stream**, the opposite of F2's 3.18× raw-UDP win. Both results are correct and measure different things: the UDP blaster has no congestion control or reliability, so it reads the carrier's raw forwarding capacity (org excellent, DERP drops 29 %); SSH is one reliable TCP stream bounded by `window / RTT` and loss-sensitive, so org's extra hop (Asahi/FR while both members are AT/DE — 86 vs 50 ms, 1.7× RTT) plus any reordering costs more than the capacity gains. ⇒ **the org relay's value is pod offload (~74×) and raw headroom, NOT universal performance**; an interactive/single-stream TCP workload is faster on the DERP floor at this relay placement. Follow-ups worth doing: (1) relay **placement** dominates — a relay near the members would likely flip this; (2) a **loss/reordering check** on the org path (the UDP arm was one-way and loss-blind by construction). Recorded in full because reporting only the flattering half would have been the misleading one. [#805 comment](https://github.com/jk-zhang-meta/MeshHarbor/issues/805#issuecomment-5491431943). |
