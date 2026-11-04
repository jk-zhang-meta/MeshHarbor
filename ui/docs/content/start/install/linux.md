---
title: Install on Linux
description: Install the MeshHarbor agent on Linux with one command — as a root systemd service or a per-user unit — including headless servers, containers and cluster nodes.
tags: [install, linux, getting-started, enrollment, headless]
order: 12
---

Linux is the most flexible of the three platforms and the one most often
installed on a machine with **no desktop session at all**. Both cases work; they
just want different flags.

## Pick a service mode first

| Mode | Flag | Runs as | Use it for |
|---|---|---|---|
| **System** | `--system` | root, systemd **system** unit | Servers, headless boxes, cluster nodes, containers, and desktops that should be on the private network from boot |
| **Per user** | *(default)* | you, systemd **user** unit | Desktops where you want to share the session you are actually logged into |

:::tip On a desktop, either works
The per-user unit shares the session you are logged into, on any desktop. A
system install also shows a GNOME or KDE desktop by itself, while the person
signed in there is at the screen, the session is unlocked, and they can be told
who is viewing. It never shows the login or lock screen on its own. Only a
system install puts the machine on the private network with its own adapter.
:::

To make an installed machine a system service later, enroll the root daemon,
then register it:

```bash
sudo meshharbord --config /etc/meshharbor/config.toml enroll --server https://meshharbor.itachi.fans --token <token> --name "$(hostname)"
sudo meshharbord service install --as-service      # alias: --system
```

It refuses until that config exists, and it says so if a per-user daemon also
runs on the machine: one daemon per machine is the rule, so stop the per-user
unit as that account (`systemctl --user disable --now meshharbor.service`).

## Install

Mint a token under **Devices → Enroll device**, then:

**Headless server / cluster node** — root systemd service:

```bash
curl -fsSL https://meshharbor.itachi.fans/api/setup/install.sh | sh -s -- \
  --role daemon --system --token <token> --server https://meshharbor.itachi.fans --name "$(hostname)"
```

**Desktop** — per-user unit:

```bash
curl -fsSL https://meshharbor.itachi.fans/api/setup/install.sh | sh -s -- \
  --role daemon --token <token> --server https://meshharbor.itachi.fans --name "$(hostname)"
```

**Tunnels only** — just the CLI, no agent:

```bash
curl -fsSL https://meshharbor.itachi.fans/api/setup/install.sh | sh -s -- \
  --role tunnel --token <token> --server https://meshharbor.itachi.fans --name "My laptop"
```

The script installs the `.deb` on Debian and Ubuntu derivatives — **x86_64 and
arm64** — or a tarball elsewhere, verifies the SHA-256, enrolls the machine, and
enables the unit.

Useful flags:

| Flag | Effect |
|---|---|
| `--download-only` | Fetch and verify the artifact, install nothing |
| `--no-enroll` | Install and set up the service, but skip enrollment (do it later) |
| `--server <url>` | Point at a self-hosted server instead of `meshharbor.itachi.fans` |
| `--uninstall` | Remove MeshHarbor from the machine — see [Uninstall](#uninstall) |

## Check it came up

```bash
mh status     # per-user install
sudo mh status # system install
```

:::warning `systemctl is-active` can lie on a system install
A machine that was enrolled before the current config convention can end up
running a perfectly healthy daemon that systemd does not own. `systemctl
is-active` then reads **inactive** while the device is online and answering.
Check `pgrep -x meshharbord` and `mh peers` before concluding anything is
wrong — and in particular, do not "restart to fix" on that basis.
:::

## Headless machines

A server with no display can still be reached as a **desktop**: the agent's
virtual-display mode gives the machine a screen, so *View screen* drops you into
a live console rather than failing. Enable it in the device's configuration
rather than by an environment variable, so the setting survives a reboot and
applies to a daemon started outside systemd.

Wayland and X11 desktops are both supported for capture and input, with
different backends underneath. Which one applies is detected at session time —
see [per-OS permissions](/docs/remote-desktop/per-os-permissions/).

## Where things live

| Item | Path |
|---|---|
| System config | `/etc/meshharbor/config.toml` |
| Per-user config | `~/.config/meshharbor/config.toml` |
| Binaries | `/usr/bin/meshharbord`, `/usr/bin/mh` |
| Logs | `journalctl -u meshharbord` (system) or `journalctl --user -u meshharbor` (per user) |

:::danger The config file holds a credential
`config.toml` contains the agent token, and — if you enable SSH — the SSH host
private key. It is written `0600`. Treat it as a secret if you copy it anywhere.
:::

## Verify what you installed

Every release asset ships a SHA-256 sidecar, a **detached GPG signature**
(`.asc`, against a published release key) and **SLSA build provenance**:

```bash
gh attestation verify meshharbord-<version>-x86_64-unknown-linux-gnu.deb \
  --repo jk-zhang-meta/MeshHarbor
```

The agent's own updater verifies the GPG signature against a key **pinned inside
the binary** before it will install anything, and refuses if the signature is
absent or does not match.

## Keeping it updated

The agent self-updates on a timer, verifying the signature before handing off to
`dpkg`. Admins can also push a specific version per device or fleet-wide.

:::warning `dpkg -i` alone does not restart the daemon
Installing a package by hand replaces the file on disk while the running process
keeps executing the **deleted inode** — so `mh --version` reports the new
version while the daemon is still the old one. Restart the unit explicitly after
a manual install.
:::

## Uninstall

One command removes everything MeshHarbor put on the machine, however it got
there: the daemon, the desktop companion and the tunnel CLI, from the `.deb`,
the `.rpm`, the tarball or the install script.

```bash
curl -fsSL https://meshharbor.itachi.fans/api/setup/install.sh | sh -s -- --uninstall
```

It stops each service through systemd **before** removing anything: the system
`meshharbord.service`, the per-user `meshharbor.service` and the update helper
(`meshharbor-update.timer` and `.path`). That stop is the daemon's clean stop, so
the routes and DNS settings it added to the machine go with it. Then the
packages and files, then the config. It prints `done.` only if every step
worked; otherwise it lists what it could not remove and exits non-zero.

| Flag | Effect |
|---|---|
| `--keep-config` | Keep `/etc/meshharbor` and `~/.config/meshharbor`: a reinstall comes back as the same device |

Then remove the device in the dashboard under **Devices**. That revokes its
credential and releases its mesh address. A device cannot do this for itself,
except an ephemeral one, which removes itself when its daemon stops.

:::note Other accounts on the machine
The config that is removed is that of the account running the command (the one
behind `sudo`), plus root's. If another account on the machine enrolled its own
per-user install, its config stays, and the command lists where it is.
:::

## Troubleshooting

- **The device never appears.** The token is single-use; mint a fresh one.
- **Installed but shows offline.** Check the unit is actually enabled and that the machine has outbound HTTPS. See [device offline or stale](/docs/troubleshooting/device-offline/).
- **Screen is black on a desktop.** The per-user unit needs a logged-in session; a root system service does not have one. See [black screen](/docs/troubleshooting/black-screen/).
- **More** → [Troubleshooting](/docs/troubleshooting/).
