---
title: Install on Windows
description: Install the MeshHarbor agent on Windows with the signed MSI, the setup wizard or one PowerShell line — and pick the right service mode for your machine.
tags: [install, windows, getting-started, enrollment]
order: 10
---

Windows has **three ways to run the agent**, and the choice matters more here
than on the other platforms: it decides whether the machine is reachable at the
lock screen, before anyone logs in, and through a UAC prompt.

## Pick a service mode first

| Mode | Runs as | Reachable when… | Use it for |
|---|---|---|---|
| **Machine — system** | `LocalSystem`, Windows service | Always: lock screen, UAC prompts, before any user logs in | Servers, unattended workstations, anything you might need at 3 a.m. |
| **Machine — attended** | Windows service, no SystemContext | A user is logged in | Shared machines where you do not want pre-logon access |
| **Per user** | Scheduled task at logon, your own account | You are logged in | Your own laptop, or where you have no admin rights |

:::tip Not sure?
Choose **Machine — system**. It is the mode that behaves the way people expect a
remote-access tool to behave, and it is the only one that can get you back into
a machine sitting at the lock screen.
:::

## Install

Mint a token in the dashboard under **Devices → Enroll device**, then use either
form. The graphical wizard asks the same questions the flags answer.

**One line, in an Administrator PowerShell** (Terminal (Admin)):

```powershell
& ([scriptblock]::Create((irm https://meshharbor.itachi.fans/api/setup/install.ps1))) -Role daemon-system -Token <token> -Server https://meshharbor.itachi.fans
```

Swap `-Role` for `daemon-machine` (attended) or `daemon-user` (per user) to
change the service mode.

**Or download the wizard** — a signed EXE with a role picker:

[MeshHarbor Setup for Windows](https://meshharbor.itachi.fans/api/setup/windows)

**Already installed and just need to enroll?**

```powershell
mh enroll --server https://meshharbor.itachi.fans --token <token> --name "$env:COMPUTERNAME" --machine-global
```

:::warning Run elevated for a machine-wide install
`daemon-system` and `daemon-machine` register a Windows service, which needs
administrator rights. Starting from a normal PowerShell prompt fails partway
through rather than at the beginning.
:::

## What gets installed

| Item | What it is |
|---|---|
| `meshharbord.exe` | The agent — remote-desktop target, mesh node, tunnel endpoint, SSH server |
| `mh.exe` | The command-line tool. A small shim that re-execs the daemon's own command surface, so the CLI and the daemon can never disagree about their version |
| `meshharbor-desktop.exe` | The tray companion: status, tunnels, and consent prompts |
| `wintun.dll` + the VC runtime | The virtual network adapter and its C runtime dependency |

Two MSI flavours exist — **per-user** and **per-machine**. The wizard and the
script pick the right one for the role you chose; you do not normally choose an
MSI directly.

## Verify what you installed

Every Windows binary is **Authenticode-signed**, and the MSI payload is signed
before packaging. Check the publisher before you trust it:

```powershell
Get-AuthenticodeSignature "C:\Program Files\MeshHarbor\meshharbord.exe" |
  Select-Object Status, @{n='Signer';e={$_.SignerCertificate.Subject}}
```

`Status` should be `Valid` and the signer should name **G ROX LTD**. The agent's
own auto-updater applies the same two checks — a valid signature *and* the
expected publisher — and refuses an update that fails either.

Then confirm it is running and enrolled:

```powershell
mh status
```

## Where things live

| Item | Path |
|---|---|
| Program files | `C:\Program Files\MeshHarbor\` (per-machine) or `%LOCALAPPDATA%\Programs\MeshHarbor\` (per-user) |
| Per-user config | `%APPDATA%\meshharbor\config.toml` |
| Machine-global config | `%PROGRAMDATA%\meshharbor\meshharbor\config.toml` |

:::danger The config file holds a credential
`config.toml` contains the agent token, and — if you enable SSH — the SSH host
private key. The machine-global directory is explicitly hardened at install
time, because ProgramData's default permissions are readable by all local users.
Treat the file as a secret if you copy it anywhere.
:::

## Keeping it updated

The agent updates itself: it polls for a new release on a timer, verifies the
signature and the publisher, checks that the artifact's own embedded version
matches what the release claimed, and only then hands off to the MSI. A build
that crash-loops is rolled back to the last known-good version automatically.

Admins can also push a specific version to one device or the whole fleet from
the dashboard.

## Uninstall

Uninstall **MeshHarbor** from *Settings → Apps → Installed apps*. If you registered
a service by hand rather than through an installer:

```powershell
meshharbord service uninstall
```

Then remove the device in the dashboard under **Devices**. That step matters: it
revokes the machine's credential and releases its mesh address back to the pool.

## Troubleshooting

- **The device never appears.** The enrollment token is single-use — if an earlier attempt consumed it, mint a fresh one.
- **It appears, then goes stale.** See [device offline or stale](/docs/troubleshooting/device-offline/).
- **Black screen when you connect.** Usually a capture problem rather than a network one — see [black screen](/docs/troubleshooting/black-screen/).
- **Antivirus blocked the download.** Installers are served through `meshharbor.itachi.fans` rather than GitHub precisely so corporate allow-lists can trust one origin. If yours blocks it, allow-list `meshharbor.itachi.fans` and retry.
