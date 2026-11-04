---
title: How devices connect
description: The connection cascade — LAN, direct internet, NAT hole-punching, then relays — how MeshHarbor picks a path, and how to see which one a pair is using.
tags: [network, nat, connectivity, troubleshooting, performance, relay]
order: 2
---

Two machines that want to talk are rarely on the same network, and are usually
both behind NAT. MeshHarbor tries a **ladder of paths** and takes the best one that
actually works — measured, not assumed.

## The ladder

:::steps
1. **Same LAN.** If both machines are on the same local network, they use it. Lowest latency available.
2. **Direct across the internet.** One or both ends is reachable at a public address.
3. **Hole-punched.** Both are behind NAT, and the two ends coordinate to open a path through it simultaneously. This is the common case, and it works far more often than people expect.
4. **Relayed.** No direct path exists. Traffic is forwarded through a relay that only ever sees ciphertext.
5. **The floor.** Where every UDP path is blocked, the mesh still runs over TLS on port 443 — the port that survives essentially every corporate network.
:::

:::badges
- **Measured, not guessed** icon:check — the choice is made from real measurements of what works, not from network-type heuristics.
- **Never ratchets down** icon:network — a pair that fell back to a relay keeps re-attempting a direct path, permanently.
- **Connectivity is never all-or-nothing** icon:shield — there is always a floor that works.
:::

## Seeing which path you are on

```bash
meshharbor peers
```

Every peer, with the path currently carrying it. The remote-desktop session
window shows the same thing as a **LAN / Direct / Relay** indicator.

## Why "relay" matters

A relay works — but it is slower and bandwidth-capped, because someone else's
machine is forwarding your packets. For remote desktop the difference is
dramatic.

:::tip If a session feels sluggish, check this first
Across a lot of field measurement, a sluggish session almost always turns out to
be a relayed pair, and the same two machines on a direct path are typically an
order of magnitude better. It is worth checking before touching any quality
setting.
:::

## The most common cause of an unexpected relay

:::warning A VPN client on one end
Corporate VPN clients frequently capture the local network range — including the
ranges private meshes use — and reroute or drop that traffic. The result is a
pair that *should* be on the LAN and instead sits on a relay, often for days,
because every surface reports the connection as fine.

The tell: two machines on the same physical network showing **Relay**. If one of
them is running a VPN client, that is your answer. Disconnecting the VPN and
watching the pair converge to direct confirms it in under a minute.
:::

Other regular causes:

| Cause | Symptom |
|---|---|
| **Symmetric NAT on both ends** | Hole-punching cannot work; a relay is genuinely correct here |
| **UDP blocked outbound** | Everything falls to the TLS floor on 443 |
| **A firewall that permits only 443** | Same |
| **One end asleep or roaming** | Transient — it re-converges |

## Make-before-break

When a better path becomes available, the new one is established **before** the
old one is torn down, so an upgrade does not interrupt a live session. The same
applies in reverse: losing a direct path falls back rather than dropping.

## What is encrypted

All of it, end to end, on every rung of the ladder. A relay forwards bytes it
cannot decrypt — putting it in the path is a performance decision, never a
privacy one.

## When it will not converge

If a pair stays relayed and you want to know why, see [cannot
connect](/docs/troubleshooting/cannot-connect/), which walks the diagnosis in
order.
