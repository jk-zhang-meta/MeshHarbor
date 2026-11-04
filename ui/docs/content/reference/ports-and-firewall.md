---
title: Ports and firewall
description: What MeshHarbor needs to reach, what it never needs opened inbound, and the one port range that matters if you self-host video calls.
tags: [reference, network, firewall, ports, self-hosting]
order: 3
---

The short version: **agents need outbound access and no inbound ports at all.**
A self-hosted server needs one HTTP port and, for video calls, a UDP range.

## What an agent needs

| Direction | What | Why |
|---|---|---|
| **Outbound TCP 443** | To your server | The control connection, and the connectivity floor |
| **Outbound UDP** | To peers and relays | Direct paths and hole-punching |
| **Inbound** | **Nothing** | Both ends connect outbound; nothing listens on the internet |

:::badges
- **No port forwarding** icon:shield — never required, on any machine.
- **No inbound firewall rule** icon:check — including for SSH, which binds nothing.
- **443 is the floor** icon:network — with every UDP path blocked, the mesh still runs over TLS on 443.
:::

## On a restrictive network

| Situation | Result |
|---|---|
| Outbound 443 only | Everything works; paths are relayed rather than direct |
| Outbound UDP permitted | Direct paths become possible |
| Outbound 443 blocked | Nothing works — this is the minimum |

If you can allow one thing, allow **outbound UDP**. It is the difference between
relayed and direct, which is the difference between usable and pleasant for
remote desktop.

## Allow-listing by hostname

The control connection and the Windows installer use your server's own origin.
Packages and updates come from GitHub's release downloads, so a corporate
allow-list needs:

| Host | For |
|---|---|
| `meshharbor.itachi.fans` — or your own server's hostname | The API, the control connection, the relay floor, the Windows installer (MSI) and the tunnel CLI |
| `github.com` and `release-assets.githubusercontent.com` | The Linux and macOS packages, the desktop companion, and every automatic update |
| `aka.ms` | Windows only: Microsoft's Visual C++ runtime, when the installer script finds it missing |

Wherever a download comes from, the agent checks it before installing: the
publisher's signature on Windows, and on Linux and macOS a GPG signature
against a key built into the agent.

## What a self-hosted server needs

| Port | Protocol | For | Exposure |
|---|---|---|---|
| Your HTTP port | TCP | API, web app, control connections, the relay floor | Behind your TLS terminator |
| The RTC range | UDP | Conference media | Reachable from participants |
| Database | TCP | The application only | **Internal** |
| Object store | TCP | The application only | **Internal** |

:::danger The conference media range does not go through your reverse proxy
Browsers send call media **straight at an address the server advertises**, on a
UDP port range. If it is not reachable, signalling succeeds perfectly and no
video ever arrives.

A small range is mapped by default — enough to try it. A real deployment wants
the full range. On Linux, host networking is the clean answer.
:::

## Optional: your own relay

A machine acting as a relay for others listens on **UDP 3478** by default.

:::tip 3478 is chosen from measurement, not convention
It is the port that the symmetric-NAT corporate population was actually measured
to reach. Higher-numbered alternatives were not, which is why this is not
configurable to a random high port and expected to work equally well.
:::

That is an inbound port on **that one machine**, and only if you deliberately
enable relaying on it. No other machine needs anything inbound.

## Verifying

From a machine:

```bash
curl -sI https://meshharbor.itachi.fans/health     # or your own server
mh netcheck                       # what this machine can actually reach
mh peers                          # which path each peer is on
```

`netcheck` is the one to read on a restrictive network: it reports reachability,
the relay verdict, floor health and NAT class as **measured**, rather than as
assumed from the firewall's configuration.
