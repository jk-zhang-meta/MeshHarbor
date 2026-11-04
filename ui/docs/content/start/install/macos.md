---
title: Install on macOS
description: Install the Roomler agent on macOS, grant the two privacy permissions it needs, and add the root half if you want the machine on the private mesh.
tags: [install, macos, getting-started, enrollment, permissions]
order: 11
---

macOS is the one platform where the agent runs as **two processes**, and it is
worth understanding why before you install — otherwise the second half looks
like a bug rather than a requirement.

## Why there are two halves

:::badges
- **The user half** icon:monitor — runs as you, inside your GUI login session. Does screen capture, input injection and clipboard.
- **The root half** icon:network — runs as root from boot. Does the overlay mesh and tunnels.
:::

Neither can do the other's job. A root process in session 0 has **no
WindowServer**, so capture and event injection simply do not work there; and
creating a `utun` interface and installing routes **requires root**. They also
cannot share one enrollment, because a second control connection for the same
device displaces the first.

:::warning A fully-featured Mac appears as TWO devices
The root half is its own enrollment, so it gets its own row — named
`<name>-daemon`. That is expected. If you only want screen sharing, install the
user half alone and you get one device row.
:::

## Install

Mint a token under **Devices → Enroll device**.

**Screen sharing only** — one token, one device row:

```bash
curl -fsSL https://roomler.ai/api/setup/install.sh | sh -s -- \
  --role daemon --token <token> --server https://roomler.ai --name "$(hostname)"
```

**Screen sharing *and* the private mesh** — mint a **second** token and pass it
as `--daemon-token`:

```bash
curl -fsSL https://roomler.ai/api/setup/install.sh | sh -s -- \
  --role daemon --token <token> --daemon-token <second-token> \
  --server https://roomler.ai --name "$(hostname)"
```

:::note The graphical installer cannot install the agent on a Mac
On macOS, [Roomler Setup](https://roomler.ai/api/setup/macos) installs only
`roomler`, the tunnel client. Install either half of the agent with one of the
commands above.
:::

`--daemon-token` is what installs the root LaunchDaemon *and* turns the overlay
on — installing that half is itself the opt-in. Without it the Mac never joins
the mesh, and it is **absent from `roomler peers` entirely** rather than showing
as offline.

Running the one-liner under `sudo` is fine: the script resolves the console user
itself and enrolls the user half as them.

## Grant the two permissions — nothing works until you do

:::danger macOS reports no error when a grant is missing
The screen streams as **wallpaper only**, and injected keys and clicks are
**silently dropped**. There is no error message anywhere. If your first session
shows a desktop with no windows, this is why.
:::

Open **System Settings → Privacy & Security** and enable **Roomler Daemon**
under both:

:::steps
1. **Screen & System Audio Recording** — without it, capture returns the desktop picture and nothing else.
2. **Accessibility** — without it, your keyboard and mouse input is dropped on the floor.
:::

You do not have to hunt for these. The **Roomler menu-bar app** names whichever
grant is missing and gives you a button per permission that opens the right
pane. The agent also probes both at startup, logs what is missing, and reports
it to the server — so the device list shows *"No screen access"* / *"No input
access"* rather than letting you discover it by connecting to a blank desktop.

Then restart the user half:

```bash
launchctl kickstart -k gui/$(id -u)/fans.itachi.meshharbor.agent
```

:::warning Grants are bound to the signed binary
macOS attributes a privacy grant to a specific bundle identity. An update that
changes that identity voids both grants, and the toggles need re-enabling. The
installer tells you when this has happened rather than leaving you to find out.
:::

## What gets installed

| Path | What it is |
|---|---|
| `/Applications/MeshHarbor.app` | The **menu-bar companion** — status, routes, and the permissions panel. No Dock tile. The only Roomler icon you should see. |
| `/Library/Roomler/meshharbord.app` | The agent itself. A background service with nothing to launch, so deliberately not in `/Applications` — but still a bundle, because the two privacy grants attach to a bundle identity. |
| `/usr/local/bin/roomler` | The CLI. |
| `/usr/local/bin/roomlerd` | The agent on `PATH`, for `roomlerd enroll` and `--version`. A symlink into the bundle, not a second copy. |

Configuration lives at `/etc/roomler/config.toml` for the root half.

## Talking to the right half

:::tip "daemon not running" usually means you asked the wrong half
The two halves listen on **different local sockets**. `roomler status` and
`roomler peers` reach the **user** half; `sudo roomler …` reaches the **root**
half. If a command reports that the daemon is not running, try it with and
without `sudo` before assuming anything is broken.
:::

## Known limits on macOS

Being explicit rather than letting you discover these:

- **No AV1.** H.264 and HEVC encode in hardware, through VideoToolbox, but Apple ships no AV1 encoder, so a Mac does not offer AV1.
- **Remote audio capture** is not available.
- **Per-org network adapters** (one Mac in several organizations, each with its own adapter) are built but not yet verified on a Mac.

## Uninstall

```bash
curl -fsSL https://roomler.ai/api/setup/install.sh | sh -s -- --uninstall
```

It stops both halves through launchd **before** removing anything: the
per-user agent and the menu-bar app (for every account that has them), then the
root half and the update helper. That stop is the daemon's clean stop, so the
routes and DNS settings it added to the Mac go with it. Then it removes
`/Library/Roomler`, `/Applications/MeshHarbor.app`, the CLI, the package receipt
and the config, which holds the credentials. It also resets the Screen Recording
and Accessibility grants, so a fresh install asks for them again rather than
showing a toggle that is on for a binary that is gone.

It prints `done.` only if every step worked; otherwise it lists what it could
not remove and exits non-zero.

| Flag | Effect |
|---|---|
| `--keep-config` | Keep the config and the two grants: a reinstall comes back as the same device |

Then remove the device row — or **both** rows, if you installed the root half —
in the dashboard under **Devices**. That revokes the credentials and releases
the mesh address.

## Troubleshooting

- **Screen is the wallpaper and nothing else** → the Screen Recording grant. See above.
- **Clicks and keys do nothing** → the Accessibility grant.
- **The Mac is missing from `roomler peers`** → you installed the user half only. Add the root half with `--daemon-token`, or enroll it (`sudo /Library/Roomler/meshharbord.app/Contents/MacOS/roomlerd --config /etc/roomler/config.toml enroll … --overlay`) and run `sudo roomlerd service install --as-service`.
- **More** → [Troubleshooting](/docs/troubleshooting/).
