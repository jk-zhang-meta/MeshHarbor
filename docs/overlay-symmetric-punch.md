# Symmetric-aware punch completion — observed-src promotion

Status: DESIGN (R3 of the corp-laptop direct-vs-relay program, 2026-08-15).
Prereqs shipped: disco observed-src wire field (NAT honesty, rc.341), the
#477 corp-VPN egress rescue, the coturn udp/443 DNAT fix (k8s-cluster-multi
`dff7fd4`). Companion planned work: R2 "VPN-adapter fallback vantage"
(gives full-tunnel hosts a real srflx); R3 does not depend on it.

## Problem

A symmetric / per-destination NAT rewrites the source mapping for every
destination. Our punch completion replies only to a peer's ADVERTISED srflx
candidates, so a symmetric↔cone pair can never promote: the cone side
receives the symmetric side's punch from a source no netmap ever advertised,
ignores it as a candidate, and keeps aiming at the (wrong) advertised
address.

Field case (2026-08-15, corplap-3 / Cisco AnyConnect full tunnel): the
CORP3 corporate egress `192.164.201.1` maps one fresh socket to ports
8467 / 8646 / 8614 across three coturn destinations — per-destination, no
usable stride, so port prediction is off the table. Observed-src completion
is the only viable path. The MBB cadence measurement (#435) already showed
the majority of never-promoting pairs are exactly this class.

## What already exists

- **Disco pongs carry the observed source** (`disco.rs` frame offset 50,
  `observed[19]`: family + 16-byte addr + port — "the source the RESPONDER
  saw"). Today it feeds NAT typing (`my_nat`) only.
- **Punch scheduling already tolerates one symmetric side**:
  `srflx_punch_worth_trying` (direct.rs) skips the punch only when BOTH
  ends are symmetric; `netmap.rs` documents the same contract.
- Disco frames are keyed/authenticated; a pong proves the peer (not a
  spoofer) saw that source.
- Pair rebuilds are epoch-guarded (the #468 raw-first swap discipline).

## Design

Receiver-side completion; the symmetric side needs no protocol change.

1. **Observed-candidate table.** When an AUTHENTICATED disco ping arrives on
   a direct sock from source `X` that matches a known peer but none of that
   peer's advertised candidates, record `X` as an *observed candidate* bound
   to `(local_sock, peer, org)`. The binding to the exact local socket is
   load-bearing: a per-destination NAT's mapping is only valid toward the
   local port the symmetric side actually dialed (our stable direct port).
   LRU per peer (cap ~4) + TTL (~2 × keepalive); refreshed by every
   authenticated arrival from `X`.
2. **Reply to the observed source.** The disco responder already answers to
   the packet source (UDP reply semantics), which is why NAT typing works.
   The change is in PROMOTION: the punch/upgrade path treats a completed
   ping↔pong exchange on `(local_sock ↔ X)` as a live direct path exactly
   as if `X` had been an advertised candidate — score it, and let MBB
   promote on that 5-tuple, epoch-guarded like any other install.
3. **Blind-punch scheduling (srflx-NONE initiators).** A node whose own
   srflx is NONE (today rendered "cannot hole-punch") can still ORIGINATE
   punches: its outbound packets toward a cone peer's advertised srflx both
   create its own NAT mapping and arrive (the cone candidate is real). Gate:
   attempt outbound-only punch rounds toward peers with advertised srflx
   even when self-srflx is NONE, at the normal MBB cadence (a few packets
   per window — negligible cost). Without this, R3 only helps once R2
   restores the initiator's srflx; with it, R3 is independent.
4. **Priority / scoring.** Observed candidates rank with advertised srflx
   (RTT-scored as usual); LAN candidates keep their existing precedence.
   `my_nat` verdicts are untouched — per-destination verdicts were honest
   and stay honest.
5. **Multi-org.** The table is per-org (per adapter/runtime), keyed like
   every other candidate structure; receiver-index demux already routes the
   packet to the right org before disco parses it.

## Security

- **Only authenticated disco installs an observed candidate.** A raw UDP
  packet from a spoofed source must never enter the table (W0 mac1 lesson;
  the C4 lesson that unauthenticated liveness lies).
- Rate-limit observed-candidate installs per peer (flood guard, cap above)
  and log every acceptance AND rejection with a counter — no silent drops.
- An observed candidate never widens permissions: it feeds the same WG
  handshake path; a wrong `X` just fails the handshake.

## Rollout

- Config-surface tribool `overlay_observed_punch`
  (`MESHHARBORD_OVERLAY_OBSERVED_PUNCH`), default ON after one cohort
  soak; env-bridge + enrollment default + list/get/set tests per the
  config-surface rule.
- Unit tests: spoofed/unauthenticated source rejected; authenticated
  observed accepted + bound to the receiving socket; LRU/TTL eviction;
  promote epoch guard; both-symmetric pairs still skipped.
- Field gate: corplap-3 (on VPN) ↔ a cone peer (devbox / cluster) reaches
  `direct` with the observed-src 5-tuple visible in `mh peers`
  detail; no regression in the cone↔cone acceptance sweep.

## Non-goals

- Port prediction for symmetric↔symmetric (both-symmetric stays relay;
  the field data shows non-strided mappings).
- LAN direct under AnyConnect lockdown (the client firewalls the physical
  NIC both directions — policy, not code; see the R8 IT-ask track).
