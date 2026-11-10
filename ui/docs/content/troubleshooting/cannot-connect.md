---
title: Cannot connect, or the session is slow
description: Diagnose a session that will not start or feels sluggish — starting with the single most common cause, a VPN client that captured the local network.
tags: [troubleshooting, network, nat, performance, relay, vpn]
order: 2
---

These are the same problem at different severities: the two ends are not on the
path they should be on.

## Start here — which path are you on?

```bash
mh peers
```

The remote-desktop session shows the same as a **LAN / Direct / Relay**
indicator.

| Reads | Verdict |
|---|---|
| **LAN** or **Direct** | The path is fine. If it is still slow, the problem is elsewhere — see [codecs and performance](/docs/remote-desktop/codecs-and-performance/). |
| **Relay** | Found it. Keep reading. |
| **Nothing at all** | The peer is not reachable — go to [device offline](/docs/troubleshooting/device-offline/) first. |

## If it says Relay

A relay works but is slower and bandwidth-capped. The causes, in the order they
actually occur:

### 1 · A VPN client on one end

:::danger This is the most common cause by a wide margin
Corporate VPN clients frequently capture local network ranges — including the
ranges private meshes use — and reroute or drop that traffic. Two machines on
the same physical network then end up on a relay, and **every surface reports
normally**, which is why this can go unnoticed for days rather than minutes.

The test takes a minute: disconnect the VPN on one end and watch the pair
converge to direct. If it does, that was it.
:::

Some enterprise VPN clients additionally **reap routes** belonging to other
software. Route guards re-assert continuously, but a client that fights hard
enough will keep a pair relayed while it is connected.

### 2 · Symmetric NAT on both ends

If both ends are behind NAT that assigns a different external port per
destination, hole-punching cannot work and a relay is genuinely the right
answer. Common on some mobile networks and a few corporate firewalls.

### 3 · UDP blocked outbound

Some networks permit only TCP 443. The mesh keeps working — that is the floor —
but it will not be direct. If a machine works everywhere except one office, this
is usually why.

### 4 · One end just moved

Roaming between networks means a period of re-convergence. It should resolve on
its own within a minute or so.

## If it will not connect at all

:::steps
1. **Is the target online?** [Device offline](/docs/troubleshooting/device-offline/).
2. **Do you have permission?** A refusal for permission reasons is reported as a refusal, not as a network failure — read the message.
3. **Is it waiting for consent?** Somebody may need to approve at the far end, and the machine may have no way to ask. See [consent](/docs/remote-desktop/consent/).
4. **Is the organization's switch on?** Remote control, remote commands and SSH each have their own organization-level switch.
5. **Do the access rules permit it?** If network ACLs are enforcing, a peer you may not reach is not in your peer list at all.
:::

## A useful asymmetry to know about

:::warning A pair can be fine in one direction and broken in the other
Path changes are not always symmetric — one end can converge to a new path
before the other. If one machine sees a peer and the peer does not see it, that
is a real state and not a display bug. It resolves, but it can take longer than
you would expect.
:::

## It works, but everything is sluggish

Confirm the path first — a relayed pair explains almost all of it. If the path
is direct and it is still slow, work through [codecs and
performance](/docs/remote-desktop/codecs-and-performance/).

## Still stuck

Gather [diagnostics](/docs/troubleshooting/collecting-diagnostics/) from **both**
ends. A connectivity problem is a property of the pair, and one side's output is
half the picture.
