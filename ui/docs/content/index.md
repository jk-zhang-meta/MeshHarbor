---
title: MeshHarbor documentation
description: Remote desktop with screen recording, a private WireGuard-style mesh with SSH and tunnels, and GPU/NPU fleet monitoring — one agent on Windows, macOS and Linux.
tags: [overview, getting-started, remote-desktop, mesh, self-hosting]
hero: hero-mesh.svg
heroAlt: Machines joined in a direct encrypted mesh with stable private addresses, crossing NATs and firewalls
order: 0
---

MeshHarbor combines **remote desktop, private mesh networking, tunnels/SSH, and GPU/NPU fleet monitoring on one small daemon**. You install **one agent per
machine**; everything else happens in a browser tab.

:::badges
- **Remote desktop & screen recording** icon:monitor — from any browser, with nothing to install on the viewing side, plus P2P file transfer and full-quality MP4 recording.
- **A private, encrypted mesh** icon:network — joining your machines wherever they are, with stable addresses, MagicDNS, exit nodes, tunnels and zero-config SSH.
- **GPU / NPU fleet visibility** icon:chip — live NVIDIA, AMD and Ascend telemetry, history, user attribution and alerts across your servers.
:::

Traffic between your machines is **end-to-end encrypted** and goes peer-to-peer
whenever a path exists. The server coordinates; it never carries your pixels,
your keystrokes or your files.

## Which path are you on?

| You want to | Start here |
|---|---|
| Reach one of your own machines from anywhere | [Quickstart](/docs/start/quickstart/) |
| Install on a specific operating system | [Windows](/docs/start/install/windows/) · [macOS](/docs/start/install/macos/) · [Linux](/docs/start/install/linux/) |
| Understand what MeshHarbor actually is before installing | [What is MeshHarbor?](/docs/start/what-is-meshharbor/) |
| Run the whole thing on your own server | [Self-hosting](/docs/start/self-hosting/) |
| Give a machine a private address other machines can reach | [Private network](/docs/network/) |
| Know what the server can and cannot see | [Security model](/docs/security/security-model/) |
| Fix something that is not working | [Troubleshooting](/docs/troubleshooting/) |

## Core capabilities

:::cards
- **Remote desktop & recording** icon:monitor — Hardware-encoded H.264, HEVC, AV1 and VP9 straight into a browser tab, with P2P file transfer, clipboard sync, keep-busy and full-quality MP4 screen recording.
- **Private network** icon:network — A WireGuard-style overlay mesh. Every device gets a stable private address and a name, and traffic goes directly between machines wherever it can.
- **Tunnels and SSH** icon:terminal — Forward a port, run a SOCKS5 proxy into a network only one machine can see, or open a resumable SSH session with no `sshd` and no open port.
- **Exit nodes** icon:external — Route all of a device's internet traffic through a machine you trust, with split-default routing that will not lock you out of your own box.
- **GPU & NPU fleet** icon:chip — Track live GPU/NPU utilization, memory, processes and alerts across enrolled compute hosts from one dashboard.
- **Self-hostable** icon:shield — One compose file, one published image. Everything above runs on infrastructure you own, with no feature held back.
:::

## Install in one line

Mint an enrollment token in your workspace under **Devices → Enroll device**,
then run the line for your operating system:

:::enroll
:::

:::tip New to MeshHarbor?
[Quickstart](/docs/start/quickstart/) walks the whole path — create a workspace,
enroll a machine, open its screen — in about five minutes.
:::

## How the documentation is organised

:::cards
- **Get started** icon:flag — Per-OS installation, enrollment, and your first remote session.
- **Remote desktop** icon:monitor — Sessions, unattended access, consent, codecs, recording and per-OS permissions.
- **Private network** icon:network — Addresses, MagicDNS, NAT traversal, subnet routers, exit nodes, tunnels and SSH.
- **Architecture** icon:blueprint — The control plane, the data planes, and what the server actually handles.
- **Security & access control** icon:shield — The security model, roles and permissions, ACLs, device policies and audit.
- **Troubleshooting** icon:wrench — Offline devices, blocked connections, black screens and collecting diagnostics.
- **Reference** icon:book — CLI, configuration keys, ports and the HTTP API.
:::
