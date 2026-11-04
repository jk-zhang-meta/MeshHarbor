---
title: The connection cascade
description: How two machines choose a path — measured rather than guessed, never ratcheting down, and with a floor over TLS 443 that always connects.
tags: [architecture, network, nat, design, connectivity]
order: 3
---

Connectivity is the hardest part of this product, and the design rests on four
commitments. They are worth stating plainly because they explain the behaviour
you will observe.

## 1 · Best path that works, always measured

The ladder — same LAN, direct public, hole-punched, relayed, then a TLS floor —
is not chosen by classifying the network. Both ends **measure** what actually
works and a decision is made from those measurements.

:::warning Heuristics may detect; they never decide
A NAT-type classifier is a useful hint and a terrible verdict. Networks lie:
middleboxes rewrite, VPN clients capture ranges, and "this looks like symmetric
NAT" is wrong often enough that acting on it strands pairs that would have
connected.
:::

## 2 · A floor that always connects

With every UDP path blocked, the mesh still runs over **TLS on port 443** — the
one port that survives essentially every corporate network, because blocking it
blocks the web.

Connectivity is therefore never all-or-nothing. It degrades in quality, not in
availability.

## 3 · Never ratchet down

A pair that falls back to a relay **keeps trying** to get back to a direct path,
permanently. There is no state in which the software has given up.

Upgrades are **make-before-break**: the better path is established before the
worse one is dropped, so improving a connection does not interrupt a live
session.

## 4 · Never self-wedge

Any change to routing, exit configuration or firewall state **pins the paths
that carry the mesh and the control connection first**, and if it cannot, it
**withholds the change** rather than applying half of it.

:::danger This is the rule that keeps a mesh feature from costing you the machine
A feature that reroutes traffic is one mistake away from removing your own
access to the box. Guards re-assert routes continuously — other VPN clients are
known to reap them — and a reconciler heals leftover state after an unclean
shutdown.
:::

## Relays

A relay forwards **ciphertext**. It cannot read what it carries, so putting one
in the path is a performance decision and never a privacy one.

Relays come in three kinds, in increasing order of preference for a given pair:

| Kind | Runs where | Notes |
|---|---|---|
| **The TLS floor** | The server | Always available; the guarantee |
| **A standard relay** | Ours, or yours | UDP; better than the floor |
| **An organization relay** | A machine **you** own | Your own hardware, your own bandwidth, your own tenancy |

An organization relay is worth knowing about if you have many relayed pairs:
because it is one of your own machines, the traffic stops crossing our
infrastructure at all, and it measurably outperforms the shared path.

:::warning An organization relay engages on a path change, not on the switch
Turning it on does not move an already-healthy pair onto it. A pair sitting
happily on the floor will not re-request until something about its path changes.
If you are testing it, restart one of the two machines to provoke the decision.
:::

## Seeing it

```bash
meshharbor peers
```

Every peer, and the path currently carrying it. The remote-desktop session shows
the same as **LAN / Direct / Relay**.

## When it does not converge

[Cannot connect](/docs/troubleshooting/cannot-connect/) walks the diagnosis. The
single most common cause is a **VPN client that captured the local network
range**, which strands a pair on a relay while every surface reports normally.
