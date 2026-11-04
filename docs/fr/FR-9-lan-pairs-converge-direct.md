# FR-9: Two nodes sharing a LAN converge to a direct carrier

**Status:** CLOSED — #741 / #744 / #746 / #747 / #758 / #765 / #782 — field-verified, shipped rc.480 → 0.4.8.

Renumbered from `FR-01` by the registry tie-break: #767 claimed `FR-1` 98 s earlier, and the
lower issue id keeps the number.

## Goal

Two enrolled nodes on the same LAN must end up on a **direct** carrier and stay there.
MeshHarbor's premise is an overlay that "just works" across networks and OSes; a pair one metre
apart falling back to a relay in another country is the most visible way that premise fails.

The trigger: six laptops on one table, one Wi-Fi, and only ONE pair was direct — the rest at
81-191 ms, i.e. relay round trips.

## Key design

Three defects, each found by following the previous one's evidence.

### 1. The demote-follow hold-down made nodes DEAF (#746)

`PathMonitor::inbound_init` (`crates/tunnel-core/src/overlay/path.rs:1249`) refuses when the
tier is suppressed, and that verdict is **authoritative for inbound** —
`handle_direct_inbound` (`crates/tunnel-core/src/overlay/runtime/inbound.rs:115`) returns
without answering the peer's WireGuard initiation at all:

```rust
let refuse = monitor_inbound.map(|v| v.is_none()).unwrap_or(false);
if refuse { record_inbound(None); return; }
```

The #30 hold-down suppresses *every* direct tier and #31 escalates it to 15 minutes, so two
ends that had both demote-followed went **mutually deaf**.

Fix: when accepting cannot cost the relay (make-before-break, incumbent is a relay), answer
regardless of suppression. `eligible` still governs everything outbound, so the hold-down
keeps its purpose — we never *promote* into a flap. Gate:
`direct::answer_while_followed()` (`overlay/direct.rs`), default ON since 0.4.2.

### 2. A just-promoted carrier was torn down by the peer catching up (#758)

The peer needs 4.2-7.4 s to finish its own probe → latch → cutover and is legitimately still
on the relay until then; those in-flight frames read as "the peer relays instead" and
triggered a follow **in the same second as the promotion**, booking a strike that escalated
the hold-down. The pair pinned itself to a relay *by the act of converging*.

Fix: `PROMOTE_FOLLOW_GRACE` (15 s) in `demote_follow`
(`overlay/runtime/establish.rs`) — a freshly promoted carrier is immune to the follow.

### 3. An accepted probe held the peer's only probe slot too long (#766)

The probe slot is **one per peer** (`overlay/path.rs:356`, "structural"), so a probe accepted
on the tier the *peer* chose blocks us from probing a tier we would rather have. Tier
deadlines are sized for an *initiated* probe that must traverse NAT.

Fix: `ACCEPTED_PROBE_DEADLINE` (8 s) in `probe_tick` (`overlay/lifecycle.rs`), applied via
`min` so it may only ever shorten.

### Observability that made all three findable

`meshharbor why <peer>` (#741) publishes the path decision — per-tier eligibility **with the
gate that actually refused**, base/q/penalty/score, and the hold-downs — and the disco prober
(#741/#744) measures candidate paths for relay-parked peers. Before these, answering "why is
this pair on relay" needed a `tcpdump` on one host and log archaeology on the other.

## Edge cases

- A peer whose LAN path genuinely does not carry must STAY on the relay. Verified: CORPLAP-2
  and CORPLAP-3 measure 100 % loss on their LAN candidates (both corp-VPN laptops) and correctly
  remain relayed.
- A peer that genuinely keeps relaying must still be followed — the grace is 15 s, not
  indefinite, and the hold-down still gates promotion.
- Mixed fleet: every gate is a config key, and `false` is the kill switch.

## Acceptance criteria

- [x] Two nodes sharing a LAN reach `tier=lan` and hold it
- [x] `meshharbor why <peer>` names the gate that refused, and cannot contradict `eligible`
- [x] A peer with a dead LAN path stays on the relay rather than flapping
- [x] A promotion is not torn down by the peer's own cutover
- [x] An accepted probe never waits longer than an initiated one
- [x] No regression in the fleet's update path across the 0.3-rc → 0.4 version switch

## Field test

Reproduce the operator's own test — `ping <overlay-ip>` from one end — and read
`meshharbor why <peer>` on both ends. Measured on the six-laptop table, before → after:

| pair | before | after |
|---|---|---|
| CORPLAP-1 | 108 ms avg (relay) | **6.7 ms** direct |
| CORPLAP-2 | 145 ms (relay) | **6.5 ms** direct |
| MacBook | 113 ms avg (relay) | **direct**, 4-5 ms floor |
| rozalina | 4-7 ms direct (control) | unchanged |

## Out of scope

- The MacBook's residual 84-95 ms inbound spikes: measured bimodal 3→169 ms on plain ICMP to
  its LAN IP with no overlay in the path, and NOT fixable from the daemon — five mechanisms
  were ruled out by measurement (ALF/pf both disabled, endpoints exact-match, inits already
  forwarded, keeping the radio busy changes nothing, AWDL down changes nothing).
- Promotion on disco evidence rather than a WireGuard handshake (was plan phase B): largely
  moot once the deafness was fixed, and not attempted.
