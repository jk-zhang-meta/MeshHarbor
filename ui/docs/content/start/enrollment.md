---
title: Enrollment and device identity
description: How an enrollment token turns a machine into a device row, what machine identity means, and how re-installing or removing a device behaves.
tags: [enrollment, install, getting-started, devices, security]
order: 13
---

Enrollment is the one step every install path shares. Understanding it explains
several behaviours that otherwise look arbitrary — why re-running an installer
does not duplicate a machine, and why removing a device is final.

## What a token is

An **enrollment token** is minted in the dashboard under **Devices → Enroll
device**. It is:

:::badges
- **Single-use** icon:check — consumed the moment a machine enrolls with it. A second attempt fails.
- **Short-lived** icon:warning — valid for about ten minutes, so a token left in a scrollback is not a standing key.
- **Scoped to one organization** icon:shield — it can only ever join a machine to the workspace that minted it.
:::

:::danger Treat a token like a password
Anyone holding a live token can join a machine to your organization. Paste it
into a terminal, not into a chat room, and mint a fresh one if it goes astray.
:::

## What happens during enrollment

:::steps
1. The installer fetches the release manifest and downloads the artifact **through your server's own origin** rather than from GitHub — so a corporate allow-list only has to trust one hostname.
2. It verifies the download: a checksum everywhere, plus a **publisher signature** on Windows and a **GPG signature** on Linux and macOS.
3. It installs the agent and registers the service or task.
4. It posts the token together with a **machine identity**, and receives back a device id and a long-lived agent credential, which are written to the agent's config file.
5. The agent opens its control connection, and the machine appears under **Devices**.
:::

## Machine identity, and why re-installing is safe

The agent derives a **stable machine identity** from the hardware, and the pair
*(organization, machine)* is unique. Re-running an installer on a machine that is
already enrolled therefore **reuses its existing device row** rather than
creating a second one.

That is what makes re-installing a safe repair step: you do not end up with a
list of ghost devices, and the machine keeps its name and its network address.

## Removing a device is final

Deleting a device in the dashboard does three things at once: it revokes the
agent credential, releases the machine's mesh address back to the pool, and
tells every other node to forget it.

:::warning A removed device does not get its old address back
Device rows are kept as a record of who held a name and an address, and the
address is recycled for the *next* joiner. If you remove a machine and re-enroll
it, it comes back with a **fresh address**. Anything you pinned to the old one —
a bookmark, a firewall rule, a config file — needs updating.

This is deliberate. "Evict" means *force a new lease*, not *ban*: a
still-authorised machine can rejoin immediately, just at a different address.
:::

## One machine, several organizations

A single machine can belong to more than one organization at a time. The first
enrollment is the **primary**; additional ones are appended alongside it.

Some things are necessarily host-global rather than per-organization — the
update channel, exit-node routing, and anything that binds a port — and those
follow the primary organization only. [Multi-org](/docs/network/multi-org/)
covers the whole model.

:::warning Joining a second organization needs a restart
The new organization's connection does not start until the agent restarts. Until
then the device looks enrolled but never comes online in the new workspace.
:::

## Ephemeral devices

CI runners, containers and autoscaled workers should not accumulate as dead rows.
For those, use a **reusable enrollment key** marked ephemeral: the device removes
itself when it stops, and a restart is treated as a new device rather than a
returning one. See [ephemeral nodes](/docs/network/ephemeral-nodes/).

## Where the credential lives

The agent writes its credential into `config.toml`:

| Platform | Path |
|---|---|
| Windows (per user) | `%APPDATA%\meshharbor\config.toml` |
| Windows (machine) | `%PROGRAMDATA%\meshharbor\config.toml` |
| Linux (system) | `/etc/meshharbor/config.toml` |
| Linux (per user) | `~/.config/meshharbor/config.toml` |
| macOS (root half) | `/etc/meshharbor/config.toml` |

:::danger This file is a credential store
It holds the agent token and, if SSH is enabled, the SSH host private key. It is
written with restrictive permissions and the machine-global directory is
explicitly hardened at install time. Do not copy it between machines — the
identity is meant to be per-machine, and a shared credential defeats the audit
trail.
:::
