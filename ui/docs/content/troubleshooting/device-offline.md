---
title: Device is offline or stale
description: A machine that was there and is not — what online, stale and offline actually mean, and the causes in the order they usually occur.
tags: [troubleshooting, devices, offline, diagnostics]
order: 1
---

## What the three states mean

| State | Means | Usually |
|---|---|---|
| **Online** | The server holds a live socket to the agent | Fine |
| **Stale** | The machine is heartbeating, but no server holds its live socket | Self-heals in about two minutes |
| **Offline** | No heartbeat at all | The machine is off, asleep, or has no route out |

:::tip "Stale" is usually not a problem
It typically means a server instance was restarted and the machine has not
re-established its connection yet. Give it two minutes before doing anything.
:::

## Work through this in order

### 1 · Is the machine on and awake?

Sleeping laptops show offline. So do machines that were shut down. Start here
before anything technical.

### 2 · Is the agent running?

:::os
@windows
```powershell
Get-Service MeshHarbor
mh status
```
@macos
```bash
launchctl print gui/$(id -u)/fans.itachi.meshharbor.agent | head -20
mh status
sudo mh status    # the root half, if installed
```
:::warning "daemon not running" often means you asked the wrong half
macOS runs two halves on two different local sockets. Try the command with and
without `sudo` before concluding anything is broken.
:::
@linux
```bash
pgrep -x meshharbord && echo running
mh status
```
:::danger Do not trust `systemctl is-active` alone here
A daemon that systemd does not own can be running perfectly while
`systemctl is-active` reports **inactive**. Check `pgrep` and `mh peers`
first — restarting on the basis of that reading can take a working machine down.
:::
:::

### 3 · Can it reach the server?

The agent needs outbound HTTPS. It does **not** need any inbound port.

```bash
curl -sI https://meshharbor.itachi.fans/health
```

If that fails from the machine, it is a network problem rather than a MeshHarbor
one — proxy, firewall, DNS or captive portal.

### 4 · Has the device been removed?

A device deleted in the dashboard has had its credential revoked. The agent will
run and never come online. Re-enroll it with a fresh token.

:::warning It will come back with a NEW address
Removal releases the mesh address for the next joiner, and re-enrolling gets a
fresh one. Anything pinned to the old address needs updating.
:::

### 5 · Did an update go wrong?

The agent rolls back a version that crash-loops. If the machine reports a
crash-loop warning:

```bash
mh status      # what version is actually running?
```

:::tip Compare the reported version with the running one
A machine that recovered by updating again can keep displaying a warning about a
version it is no longer running. If the reported failing version is not what is
installed now, the machine is healthy and the warning is stale.
:::

### 6 · A manual package install that did not restart

:::danger Installing a package by hand does not restart the daemon
The file on disk is replaced while the running process keeps executing the
deleted one — so `mh --version` reports the **new** version while the
daemon is still the old one, and any fix you just installed is not running.
Restart the service explicitly after a manual install.
:::

### 7 · Two service definitions

If a machine restarts in a loop, check for **two** enabled units trying to run
the same agent. The tell is a service that is perpetually in an
auto-restarting sub-state while looking green at a glance.

## Green in the list, but remote control says the device is unavailable

The device list's status is heartbeat-based, while a remote session needs the
live socket. A machine whose connection is half-open — something in the middle
still answering keepalives after the far end went away — shows **green** and
still refuses a session.

Recent agents detect this themselves and reconnect within about two minutes. If
it persists, restart the agent.
