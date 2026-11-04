---
title: Private network
description: A WireGuard-style encrypted mesh between all your machines — stable private addresses, names, direct connections through NAT, tunnels, exit nodes and SSH.
tags: [network, mesh, overview, wireguard, magicdns]
hero: private-network.svg
heroAlt: Home, office and cloud machines joined into one private encrypted network with stable addresses
order: 0
---

Every machine you enroll can also join a **private encrypted mesh**. Each one
gets a **stable private address** and a name, and they talk **directly to each
other** wherever they are — across NAT, across the internet, without opening a
single inbound port on anything.

:::badges
- **Stable addresses** icon:network — an address that does not change when the machine moves between networks.
- **Direct where possible** icon:check — traffic goes machine-to-machine, not through us, whenever a path exists.
- **No inbound ports** icon:shield — nothing is exposed to the internet; connections are established outbound from both ends.
:::

## What you get

:::cards
- **[Addresses and MagicDNS](/docs/network/addresses-and-magicdns/)** icon:network — Stable private addresses, and names instead of numbers.
- **[How devices connect](/docs/network/how-devices-connect/)** icon:compare — The path cascade: LAN, direct, hole-punched, relayed — and how to see which one you are on.
- **[Subnet routers](/docs/network/subnet-routers/)** icon:blueprint — Expose an entire LAN through one machine.
- **[Exit nodes](/docs/network/exit-nodes/)** icon:external — Route all of a device's internet traffic through a machine you trust.
- **[Tunnels](/docs/network/tunnels/)** icon:terminal — Forward a single port to a service on a remote machine.
- **[SOCKS5](/docs/network/socks5/)** icon:external — A proxy into a network only one of your machines can see.
- **[SSH](/docs/network/ssh/)** icon:shield — A shell on any node, with no `sshd` and no open port.
- **[Multi-org](/docs/network/multi-org/)** icon:compare — One machine in several organizations at once.
- **[Ephemeral nodes](/docs/network/ephemeral-nodes/)** icon:flag — Devices that remove themselves: CI runners, containers, autoscaled workers.
:::

## The two commands you will actually use

```bash
mh status    # this machine: address, name, and how it is connected
mh peers     # everything else on the mesh, and how each one is reached
```

`mh peers` is the diagnostic. It names every peer, its address, and the
path currently carrying it — which answers "why is this slow?" faster than
anything else.

## Turning it on

The mesh is part of the agent, not a separate install. On Windows and Linux it
comes up with the agent. On macOS it needs the **root half** of the install,
which is a second enrollment — see [Install on
macOS](/docs/start/install/macos/).

:::warning An organization can have the mesh switched off
A device can be perfectly connected to the control plane and still have no mesh
— they are separate things. `mh status` prints both on one line for exactly
that reason, and an organization whose mesh is off is **named** in `meshharbor
peers` rather than silently omitted.
:::

## What the server does, and does not do

The server hands each machine the list of peers it is allowed to reach, and
helps two machines find each other. It **never carries your traffic in the
clear**: when no direct path exists at all, the fallback relay forwards
**ciphertext** it cannot read.

That is the whole trust model in a sentence, and
[architecture](/docs/architecture/what-the-server-sees/) spells out the details.
