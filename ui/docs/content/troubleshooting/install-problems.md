---
title: Install problems
description: The installer fails, antivirus blocks it, or the machine never appears afterwards — per-OS causes and the fixes that actually work.
tags: [troubleshooting, install, windows, macos, linux, enrollment]
order: 5
---

## It installed, but the machine never appeared

### The token was already used

Enrollment tokens are **single-use**. If an earlier attempt got far enough to
enroll, the token is spent and the retry fails. Mint a fresh one.

### The wrong server

If you are self-hosting, the machine must be pointed at *your* server. A script
served by your own instance names your origin automatically — but a command
copied from elsewhere may not.

```bash
mh status    # which server does it think it belongs to?
```

### It cannot reach the server

The agent needs outbound HTTPS and no inbound ports. From the machine:

```bash
curl -sI https://meshharbor.itachi.fans/health
```

Failing here is a network problem — proxy, firewall, DNS or captive portal.

## Antivirus or endpoint protection blocked it

:::tip Which hosts an allow-list needs
The Windows installer (the MSI) and the tunnel CLI are served through
`meshharbor.itachi.fans` (or your own server), so for those one hostname is enough. The
Linux and macOS daemon packages, the desktop companion and every automatic
update come from GitHub's release downloads, so an allow-list also needs
`github.com` and `release-assets.githubusercontent.com`, the host GitHub
redirects downloads to. On Windows the installer script also fetches
Microsoft's Visual C++ runtime from `aka.ms` when it is missing. If a download
is blocked, allow-list those and retry.
:::

Every Windows binary is Authenticode-signed by **G ROX LTD**, and Linux/macOS
artifacts carry GPG signatures and build provenance — useful evidence when
asking a security team for an exception. See [signed
releases](/docs/security/signed-releases/).

## Per-OS

:::os
@windows
**"Access denied" partway through.** A machine-wide install registers a Windows
service and needs administrator rights. Run from an elevated PowerShell.

**Installed, but not reachable at the lock screen.** That is the service mode,
not a failure. Re-install with `-Role daemon-system`.

**A previous version will not uninstall.** Remove it from *Settings → Apps* and
retry. If a manually-registered service is in the way:

```powershell
meshharbord service uninstall
```

@macos
**The Mac shows as two devices.** Expected — the root half is its own
enrollment. See [Install on macOS](/docs/start/install/macos/).

**The Mac is missing from `mh peers` entirely.** You installed the user half
only. Add the root half by re-running with a second token as `--daemon-token`.

**Everything installed, screen is wallpaper.** A privacy grant, not an install
problem — see [black screen](/docs/troubleshooting/black-screen/).

**"daemon not running".** You are probably talking to the wrong half. Try with
and without `sudo`.

@linux
**Installed, but shows offline.** Check the unit is enabled and that the machine
has outbound HTTPS:

```bash
pgrep -x meshharbord
journalctl -u meshharbor -n 50 --no-pager
```

:::danger Do not judge by `systemctl is-active` alone
A perfectly healthy daemon can be one systemd does not own, and `is-active` then
reports **inactive**. Check `pgrep` and `mh peers` before restarting
anything.
:::

**A restart loop.** Look for **two** enabled units trying to run the same agent.
The tell is a service perpetually in an auto-restarting sub-state.

**Manual package install seemed to do nothing.** `dpkg -i` replaces the file
without restarting the service — so the version command reports the new build
while the old one is still running. Restart the unit.
:::

## Uninstalling cleanly

Each OS has its own steps on its install page. Two things people forget:

:::steps
1. **Remove the device in the dashboard.** That is what revokes the credential and releases the mesh address.
2. **On macOS, clear the privacy grants.** They are bound to the binary you deleted, so a fresh install otherwise shows a toggle that is on but attached to nothing.
:::
