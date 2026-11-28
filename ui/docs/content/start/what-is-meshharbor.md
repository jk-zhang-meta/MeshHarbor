---
title: What is MeshHarbor?
description: MeshHarbor combines browser remote desktop with recording, a private WireGuard-style mesh with SSH/tunnels, and GPU/NPU fleet monitoring on one agent.
tags: [overview, getting-started, architecture, remote-desktop, mesh]
hero: private-network.svg
heroAlt: Home, office and cloud machines joined into one private encrypted network with stable addresses
order: 1
---

Most people arrive here already running separate tools: something like
**TeamViewer or RustDesk** to see a screen, something like **Tailscale or a
VPN** to reach a service, and separate scripts or dashboards to watch GPU
servers. MeshHarbor is one lightweight agent that handles all of them on one
identity and one server you can host yourself.

:::video C1YdfmhbAKM
A 9-minute tour: installing the agent on Windows, macOS and Linux, connecting
from a browser tab, and how it compares with TeamViewer and AnyDesk.
:::

## Core pillars

### 1 · Desktop sharing, remote control and screen recording

Any machine you enroll becomes reachable as a **live screen in a browser tab**.
There is nothing to install on the viewing side — the controller is a plain
browser, best in Chrome, Edge or another Chromium browser, and Safari and Firefox
work too. Video is hardware-encoded where the hardware allows
(H.264, HEVC, AV1, VP9), input is injected on the far end, clipboard and P2P
file transfer ride their own data channels, and optional full-quality MP4 screen
recording runs locally on the device.

### 2 · Your own private network

Every enrolled machine also gets a **stable private address** on an encrypted
overlay mesh, and a name you can use instead of the address. Traffic goes
**directly between machines** whenever a path exists, hole-punching through NAT;
when no direct path exists it falls back through relays, and it keeps
re-attempting a direct upgrade rather than staying relayed.

On top of the mesh sit **port forwards**, a **SOCKS5 proxy**, **exit nodes**,
**network zones**, and **SSH to a node that runs no `sshd` and has no open port**.

### 3 · Fleet & GPU/NPU monitoring

Enrolled machines report live status, versions, and — for compute hosts —
**NVIDIA, AMD, and Ascend GPU/NPU utilization, memory, processes and alerts** so
you can manage workstations and AI servers from the same console.

## Two invariants worth knowing up front

These two shape almost every design decision, and knowing them explains a lot of
the product's behaviour.

:::badges
- **One daemon per machine** icon:shield — The agent is simultaneously the remote-desktop target, the mesh node, the tunnel endpoint and the SSH server. It is not four cooperating services, which is why "just install another copy" is almost always the wrong answer.
- **The server coordinates, it never carries plaintext** icon:network — Pixels, keystrokes, SSH bytes and tunnel payloads travel peer-to-peer, or over a relay that only ever sees ciphertext.
:::

## What runs where

| Piece | What it is | Where it runs |
|---|---|---|
| **The agent** (`meshharbord`) | A native binary — the remote-desktop target, the mesh node, the tunnel endpoint, the SSH server, and GPU/NPU telemetry | Every machine you enroll |
| **The CLI** (`mh`) | Status, peers, tunnels, exec, ssh, diagnostics | Same machine, alongside the agent |
| **The server** | Accounts, device registry, signalling, coordination, audit, and GPU alert evaluation | MeshHarbor's cloud, or your own |
| **The controller** | A browser (Chromium browsers work best; Safari and Firefox work too) | Wherever you happen to be |

## What it is *not*

Being straight about this saves time:

- **Not a server-side session-recording product.** Remote sessions are audited — who connected, when, from where — and optional screen recordings stay on the device and transfer peer-to-peer; the pixel stream itself is deliberately never stored server-side.
- **Not a full MDM.** You can enroll, update, configure and audit devices; you cannot push arbitrary software or manage OS policy.
- **Not a public-relay service by default.** A relay is a fallback for when no direct path exists, not the normal path.

## Where to go next

:::cards
- **[Quickstart](/docs/start/quickstart/)** icon:flag — Workspace to first remote session in about five minutes.
- **[Install on your OS](/docs/start/)** icon:download — Windows, macOS and Linux each have their own page.
- **[Security model](/docs/security/security-model/)** icon:shield — Exactly what the server can and cannot see.
- **[Self-hosting](/docs/start/self-hosting/)** icon:terminal — One compose file, one published image.
:::
