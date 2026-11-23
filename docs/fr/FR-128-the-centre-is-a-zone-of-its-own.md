# FR-128: The centre is a zone of its own — a device reaches it through its zone's entry

> **Status:** in progress — claimed 2026-11-23; P1 live on server 0.4.209 and one gateway (2026-11-23), field-verified on a throwaway device. Tracking issue: none (GitHub Issues are disabled on
> `jk-zhang-meta/MeshHarbor`); this spec and its registry row are the record.

## Goal

Today every enrolled device must reach the centre **directly** over TCP 443. Management traffic is
exempt from the zone rules ([business isolation](../business-isolation.md), "Management is exempt"),
so the zone model routes every connection except the one that keeps a device on the fleet. That has
two costs:

1. **One blocked path takes a device off the fleet.** On 2026-11-23 three mainland lab servers on
   one subnet lost every route to the centre's address at about 01:04Z (ICMP and TCP 80/443 silent).
   The rest of the internet, the lab's other subnet and a mainland relay stayed reachable. The
   centre reaped their sockets 104 s later, and they stayed offline, although their daemons ran and
   still held direct mesh paths (RTT ≤ 1 ms) to a peer on the other subnet.
2. **A strict zone's devices hold a direct cross-border connection** to the centre: the one
   connection the zone model never routes.

The centre becomes a zone of its own. A device whose zone may not reach the centre directly (the
FR-124 verdict) reaches it **through one of its zone's gateways**, which forwards the management
connection to the centre. Every other device still dials the centre first and falls back to its
zone's gateways when that fails. The device keeps end-to-end TLS with the centre: a gateway sees
only ciphertext and forwards only to the centre.

```mermaid
flowchart LR
  subgraph "strict zone (mainland)"
    D1[device] -- "TCP: TLS to the centre, opaque" --> G[zone gateway<br/>management entry]
    D2[device on the gateway's LAN] --> G
  end
  subgraph "other zone"
    D3[device] -- "direct first" --> C
    D3 -. "fallback" .-> G2[its gateway]
    G2 --> C
  end
  G -- "forwards only to its own centre" --> C[(centre)]
```

## Key design

### Who is an entry

- A zone's **entries are its approved gateways** (`zone.gateway_relay_ids`, read in
  `crates/modules/network/src/network_zones.rs:161`) that run a management entry. A device runs
  one when it has the device-owned key `management_entry_port` set (default `0` = off). The key is
  absent from `DesiredConfig`, and it is refused under `protected` (FR-127). So two parties
  agree: the device's owner opens the port, and the org admin made the device a gateway.
- An entry's dialable addresses are the gateway's public addresses, the same candidates
  `relay_endpoints` uses for the relay port (`crates/modules/network/src/org_relay.rs:2332`), each
  paired with the entry port, plus the IPs of the admin's static endpoints. They are public
  literals only (the same SSRF rule), because a server-pushed dial target is a port scanner run by
  every device in the zone.
- A device-owned `management_entries` list (`ip:port`, any address, including a LAN peer) is set
  by the device's owner. It is tried before the pushed entries.

### What a device may do

- **Direct is allowed** exactly when FR-124 lets the device's zone use the centre
  (`zone_central_relay_ok`, `network_zones.rs:178`). A `RouterOnly` zone whose infrastructure
  countries do not hold the centre gets no direct path. Every other zone, an org with no zones, and
  a device with no resolved zone keep direct first.
- The centre pushes `rc:agent.management_path { direct, entries }` after hello, and again when the
  device's verdict or entry list changes. The device persists it next to its config: it is state,
  not configuration.
- **The device is never stranded.** If a device whose zone forbids direct has had every entry fail
  for a whole round, it dials the centre directly as a last resort and says so in its log (P2
  shows it in `mh status` and on the zone page). Business isolation requires a mainland device to
  stay manageable.

### The device's path ladder

1. The path that last worked.
2. Then, in order: direct (if allowed), local entries, pushed entries.
3. A candidate fails on TCP connect, TLS or the WebSocket handshake, within 15 s.
4. Direct comes first again at every reconnect while it is allowed, so a device that fell back
   to an entry returns to direct the next time its socket reconnects (P1). A periodic direct
   probe that moves a live socket back sooner is P2.
5. A socket on the direct path by choice moves onto an entry when a push forbids direct
   (`should_move`). A socket that is direct as a last resort does not, or it would loop.

HTTP requests to the centre take the control socket's current path: the client resolves the
centre's host to the entry address, so SNI and the certificate check are unchanged. P1 covers
token renewal, the update check and download, crash upload, the device name, the log uploader
(it rebuilds its client when the path changes) and the LocalAPI device view (0.4.210). The boot
preflight does not probe the centre's address when the kept path sends the device to its entries.
Still direct: the Windows SYSTEM services (another process), and enrollment and sign-in (P3).

### The entry forwarder

```mermaid
sequenceDiagram
  participant D as device
  participant E as entry (gateway)
  participant C as centre
  D->>E: TCP, "MHE1 attest <nonce>"
  E-->>D: "MHE1 ok <token>" (signed: entry id, D's source ip, time, nonce)
  D->>E: TCP, TLS ClientHello (SNI = centre)
  E->>C: TCP to its own centre, bytes copied both ways
  D->>C: GET /ws?role=agent&entry=<token> (inside TLS)
  C->>C: verify token, origin = D's attested ip
```

- It listens on `0.0.0.0:<port>` and `[::]:<port>`. Each connection is one of two kinds:
  - It starts with `MHE1 `: an attestation request. The entry answers one line and closes.
  - Anything else is forwarded raw to the host and port of the entry's own `server_url`, resolved
    by the entry.
- The destination never comes from a message.
- Limits: 1024 concurrent connections, 32 per source address, a 10 s upstream connect, and 180 s
  idle (the control socket pings every 25 s).

### A zone through an entry

The centre sees the entry's address. Left alone, a device would take the entry's zone. An entry
must not lend its zone, so:

- **Attestation.** The token's payload is `{e: entry id, ip: source ip as the entry saw it, t: unix
  secs, n: nonce}`, signed with HMAC-SHA256 under the entry's key. The key is
  `HMAC(server secret, "fr128-entry-v1" ‖ entry id ‖ token generation)`. It is sent to the entry in
  `rc:agent.management_entry { key }`, and only while the entry is an approved gateway with a port.
- **The check at upgrade.** The device sends the token as `entry=` on `/ws?role=agent`. The centre
  accepts it only when all of these hold:
  1. the HMAC verifies;
  2. `|now − t| ≤ 120 s`;
  3. the entry is a live agent of the **same tenant**, currently an entry;
  4. the connection's own client address (the trusted chain) is the entry's last observed public
     address.

  Then the connection's origin is the attested address (a new `ConnectionOriginSource::
  ManagementEntry`, `crates/core/src/client_ip.rs:111`). Zone, GeoIP and `public_ip` read it as if
  the device had dialed directly. An attested address that is private (a device on the entry's own
  network) keeps the entry's address, which is then the true one.
- **A connection from the address of one of its org's current entries, with no valid token, gets
  no client address**, so its zone is unresolved. Only the org's current entries count (approved
  relay, zone gateway, port set): the port is the owner's setting, and an unapproved device or
  another org's must not be able to strip the address of everyone behind a shared egress (found
  by the P1 tests). A pin (`app.business_zone_pins`) still applies. The cost: a device behind
  the same NAT as an entry, dialing directly, gets no zone either. Give an entry an address of its
  own, or pin its neighbours. An approved relay is exempt: two relays of one provider can share an
  egress (seen in the field), and a relay that lost its zone would lose its lines.
- An entry is trusted with its key: a gateway already relays its zone's traffic. A compromised
  entry could attest a wrong address for devices that come through it. It cannot read or forge
  their TLS.
- Residual: no nonce is remembered, so a token can be replayed for up to 120 s, and only from the
  entry's own address by a device of the same org. A device whose owner points it at ANOTHER
  org's entry, without a token, takes that entry's address (the no-token rule is per org).

### Kill switches

| Where | Switch | Effect |
|---|---|---|
| device | `MESHHARBORD_MANAGEMENT_ENTRIES=0` | direct only, today's behaviour |
| entry | `management_entry_port = 0` | no listener, no key |
| centre | `app.management_entries = false` | tells every device "direct, no entries" and ignores tokens |

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P1 | entry forwarder and attestation, the device's path ladder (WebSocket and the main HTTP clients), the centre's push and token check, zone through an entry | all three above | built, not released |
| P2 | the zone page shows each zone's entries and every device's current path; `mh status` shows it; a periodic direct probe moves a live socket back; the remaining HTTP clients | — | open |
| P3 | install and sign-in carry the org's entry list, so a fresh install in a strict zone never dials the centre | — | open |
| P4 | browser access (web console, remote-desktop viewer) through a zone's entry | — | open |
| P5 | an entry caches release assets, so updates do not cross the line once per device | — | open |

## Acceptance criteria

- [x] **AC1 (field).** A device whose direct path to the centre is blocked comes online through its
  zone's entry, and its zone stays the one its own address gives. Shown failing first. (2026-11-23,
  field log: red with the device's switch off, green through the gateway; the centre recorded the
  device's own address. The device's zone was pinned for the run, so the address, not a GeoIP
  zone, is what was shown.)
- [ ] **AC2 (field).** While an entry works, a device in a strict zone whose countries exclude the
  centre has no direct TCP connection to the centre.
- [x] **AC3.** None of these moves a zone (tests, `management_entry_tests.rs`, 8 pass): a token from another tenant's entry, an expired
  token, a forged token, a token presented from an address that is not the entry's. A current
  entry's address with no token gets no zone.
- [x] **AC4.** Each kill switch restores direct connection within one reconnect. (The device's
  switch in the field run; the centre's in `with_management_entries_off_…`.)
- [x] **AC5 (docs).** [Business isolation](../business-isolation.md) gains "Management through an
  entry" (diagrams, anchors), and the docs index row in [docs/README.md](../README.md) names it.

## Open decisions

- **Last-resort direct for a strict zone** is on: it keeps a device manageable when its zone's
  entries are all down. A per-zone "never direct" setting can follow.
- Whether entries also carry tunnel clients and browsers (P4).

## Out of scope

- A second centre, or failover of the centre itself.
- Moving management onto the overlay. The control socket deliberately does not ride the mesh: the
  diagnostics it carries are needed most when the mesh is broken ([fleet RPC](../fleet-rpc.md)).

## Field log

| When (UTC) | What |
|---|---|
| 2026-11-23 ~01:04 | Red, before any change. Three lab servers on one subnet go silent on the control socket together; the centre reaps them at 01:05:41 (`receive-liveness deadline exceeded`, 104–108 s). From one of them: the centre's address answers no ICMP or TCP 80/443, while public sites, a mainland relay (TCP 22 open; other ports answer RST, so reachable) and a peer on the lab's other subnet all answer. That peer reaches the centre normally. The daemons keep running, with direct mesh paths to that peer. |
| 2026-11-23 01:27–01:54 | The route came back by itself, one server at a time (01:27, 01:37, 01:54); one of them still had no route at 01:32 when tested. About 25–50 min off the fleet each, with the daemon running and the zone's gateway reachable the whole time. A later field run needs its own red: a host whose path to the centre's address is blocked on purpose (an outbound firewall rule, reverted after). |
| 2026-11-23 | Released as 0.4.209 for the field run (server; the agent only on the hosts of the run, no fleet release). |
| 2026-11-23 05:43 | Server 0.4.209 cut over (24/26 online before and after, no panic, meeting settings kept). The agent 0.4.209 installed by hand on one mainland gateway only (backup kept), `management_entry_port = 18443`: listening, attestation key received. ⚠️ The first try lost the key: written into the config while the OLD daemon ran, it was dropped when that daemon saved its config (an older build does not know the key). Set it through the NEW daemon (`mh config set`), then restart. |
| 2026-11-23 05:46 | A throwaway device (a network namespace on a Singapore host, its own user and config, enrolled ephemeral, pinned to the strict mainland zone), direct path open: told `direct=false entries=1`, moved onto the entry, connected in 6 s. The centre recorded the device's own address, not the gateway's. But one direct connection to the centre stayed open: a client not yet routed (the startup preflight logged a direct attempt; the log uploader and the device view also build their clients once). **AC2 not met in P1.** |
| 2026-11-23 05:47–05:50 | Centre address dropped inside the namespace (other sites reachable, as in the lab outage). Red: the device's switch `MESHHARBORD_MANAGEMENT_ENTRIES=0`: every connect `connect to <centre>:443 timed out`, device offline. Green: switch off: online through the entry, own address recorded, 0 direct connections, 1 through the entry. The first entry try hit the 15 s per-path bound; the next round took 3 s, so the bound may be tight on a cross-border line. Rig removed, device deleted; the gateway keeps its entry. |
| 2026-11-23 | 0.4.210: the log uploader, the device view and the boot preflight follow the path too (the direct connection the field run saw); a path's bound 15 s → 25 s. Linux agent release. |
