---
title: The agent
description: What roomlerd actually is, why it is a single process rather than several, how it runs on each OS, and how it keeps itself updated safely.
tags: [architecture, agent, design, windows, macos, linux]
hero: devices.svg
heroAlt: One agent binary on each machine, serving remote desktop, the mesh, tunnels and SSH at once
order: 2
---

`roomlerd` is one native binary that is, simultaneously:

:::badges
- **The remote-desktop target** icon:monitor — capture, encode, input injection, clipboard, file transfer.
- **A mesh node** icon:network — its own encrypted tunnel interface, peer discovery, path selection.
- **A tunnel endpoint** icon:terminal — the far end of forwards and SOCKS5 connections.
- **An SSH server** icon:shield — with no `sshd` and no bound port.
:::

## Why one process

The parts are not independent. The mesh's path selection and the remote-desktop
session want the same measurements about the same peers. The SSH server needs to
sit inside the packet path the mesh owns. A tunnel and a remote session compete
for the same bandwidth, and something has to arbitrate.

More practically, the machine only has one of several things:

| One per machine | Consequence |
|---|---|
| The network adapter, with a fixed name | Two agents cannot both own it |
| The local control socket | The CLI would not know which to talk to |
| Routing, firewall and DNS state | Two agents would fight over it |
| The updater | Two would race to replace each other's binary |

:::danger This is why "install a second copy" is the wrong answer
It is the intuitive fix for wanting a machine in two organizations, and it
breaks on every row of that table. One agent with several enrollments is the
supported shape — see [multi-org](/docs/network/multi-org/).
:::

## How it runs, per platform

:::os
@windows
A Windows service (`LocalSystem`) or a scheduled task, depending on the install
mode you chose. The system service is the one that can reach the lock screen and
the pre-logon desktop.

Alongside it: `roomler.exe` — a small shim that re-execs the agent's own command
surface, so the CLI and the daemon can never disagree about their version — and
`meshharbor-desktop.exe`, the tray companion.

@macos
Two processes, because macOS forces it: a **LaunchAgent** in your GUI session
does capture and input (a root process in session 0 has no WindowServer), and a
**LaunchDaemon** as root does the mesh and tunnels (creating a network interface
needs root).

A third, small root helper owns updates — neither working half should ever exec
its own replacement.

@linux
A systemd unit, either a root system service or a per-user unit. The per-user
form shares the session you are logged into; the system form is for headless
machines, where virtual-display mode gives it a screen to capture.

Both X11 and Wayland are supported, detected at session time rather than cached
at startup.
:::

## Configuration

One `config.toml` per machine: the server URL, the credential, and per-machine
settings — encoder preference, mesh mode, declared tunnel routes, whether SSH
and remote commands are permitted at all.

:::danger It holds a credential
The agent token, and the SSH host private key if SSH is enabled. Written with
restrictive permissions; the machine-global directory is hardened at install
time. Do not copy it between machines.
:::

Some settings can be changed from the dashboard, but **only if the machine opted
in** to being remotely configurable. That opt-in is itself device-local and
structurally cannot be set by the server — otherwise the last gate would not be
a gate.

## Self-update

The agent updates itself, and the update path is where most of its defensive
engineering lives:

:::steps
1. It fetches the release manifest through **your server's** origin, not GitHub — so a corporate allow-list only has to trust one host.
2. It verifies the **publisher signature**: Authenticode on Windows, GPG against a key pinned inside the binary on Linux and macOS.
3. It checks that the version **inside** the signed artifact matches what the manifest claimed — so a tampered manifest cannot point a "new" release at a genuinely-signed older build.
4. It installs, restarts, and **rolls back** if the new version crash-loops.
:::

:::warning A checksum alone would prove nothing here
The hash arrives in the same manifest, from the same origin, as the download URL
— anyone who can serve one can serve the other. The anchor has to be a signature
against a key published in advance, which is why the pinned key exists.
:::

## Resource use

Idle, the agent is small: a control connection, a heartbeat and occasional path
measurement. Capture and encoding only run while someone is connected. The mesh
costs a keepalive per peer.
