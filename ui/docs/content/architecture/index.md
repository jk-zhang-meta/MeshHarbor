---
title: Architecture
description: How MeshHarbor is put together — one control plane, three data planes, one agent per machine, and a server that coordinates without ever carrying your traffic.
tags: [architecture, overview, security, design]
order: 0
---

MeshHarbor's shape follows from two invariants. Almost every design question in the
product is answered by one of them.

:::badges
- **One daemon per machine** icon:shield — the agent is simultaneously the remote-desktop target, the mesh node, the tunnel endpoint and the SSH server. Not four services.
- **The server coordinates, never carries plaintext** icon:network — pixels, keystrokes, SSH bytes and tunnel payloads go peer-to-peer, or through a relay that only sees ciphertext.
:::

## Control plane, data planes

There is **one control plane** — accounts, permissions, the device registry,
signalling — and **three data planes** that it introduces but does not carry:

| Data plane | Carries | Path |
|---|---|---|
| **Remote desktop** | Video, input, clipboard, files | Peer-to-peer, relay fallback |
| **Private network** | Whatever you send over the mesh | Peer-to-peer, relay fallback |
| **Conferencing** | Call audio and video | Through the server's forwarding unit |

:::warning Conferencing is the deliberate exception
A selective forwarding unit has to receive and re-send media; that is what makes
a multi-party call practical. The other two planes never work this way. It is
worth knowing which feature is which — see [what the server
sees](/docs/architecture/what-the-server-sees/).
:::

## Read on

:::cards
- **[System overview](/docs/architecture/system-overview/)** icon:blueprint — The pieces, and how a request moves through them.
- **[The agent](/docs/architecture/the-agent/)** icon:terminal — What runs on a machine, and why it is one process.
- **[Connection cascade](/docs/architecture/connection-cascade/)** icon:compare — How two machines find the best path that works.
- **[What the server sees](/docs/architecture/what-the-server-sees/)** icon:shield — Precisely what is and is not visible to the control plane.
:::

## Why "one daemon" keeps coming up

Because it explains answers that otherwise look unhelpful. *"Can I run a second
copy for my other organization?"* — no, and not out of licensing: the agent owns
a network adapter with a fixed name, a single local control socket, host-global
routing and firewall state, and one updater. Two copies fight over all of them.

The supported answer is one agent with several enrollments — see
[multi-org](/docs/network/multi-org/).
