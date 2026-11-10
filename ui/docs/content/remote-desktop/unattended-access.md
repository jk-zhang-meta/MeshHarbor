---
title: Unattended access
seoTitle: Unattended access, even at the lock screen — MeshHarbor
description: Unattended remote access to your own servers and workstations — nobody approves at the far end, even at the Windows lock screen or before anyone logs in.
tags: [remote-desktop, unattended, windows, linux, access-control]
order: 2
---

Unattended access is two separate things, and people usually want both:

:::badges
- **Nobody has to approve** icon:check — the machine does not prompt before handing over its screen.
- **Nobody has to be logged in** icon:monitor — the machine is reachable at the lock screen, or with no session at all.
:::

They are configured in different places, because they are different risks.

## 1 · Skip the prompt

Set the device's consent mode to **Automatic**. See
[consent](/docs/remote-desktop/consent/) for the full set of modes and why an
absent setting means *ask*.

:::warning Set this per device, deliberately
"Automatic" means anyone with permission to view that device gets its screen
with no human in the loop. That is exactly right for a rack server and exactly
wrong for a colleague's laptop.
:::

## 2 · Be reachable with nobody logged in

This is an operating-system problem, and the answer differs per platform.

:::os
@windows
Install with the **Machine — system** service mode. The agent then runs as a
Windows service under `LocalSystem` and can reach the secure desktop — the lock
screen, UAC prompts, and the login screen before anyone has signed in.

The other two modes cannot do this: an attended machine service has no access to
the secure desktop, and a per-user task does not exist until you log in.

If you installed in another mode, re-run the installer with
`-Role daemon-system`.

@macos
macOS has no equivalent. Screen capture requires a **GUI login session** — a root
process in session 0 has no WindowServer and cannot capture anything, no matter
how it is configured.

In practice a Mac must be logged in (it may be locked) to be reachable as a
desktop. The root half of the install exists for the mesh and tunnels, not for
capture.

@linux
Three options, depending on the machine.

**A machine with a desktop** — install the per-user unit and it shares the
session you are logged into, on X11 or Wayland. It starts when you log in.

**A system install** (`--system`) runs as root from boot. On GNOME and KDE it
shows the desktop of the person signed in at the screen by itself, while that
session is unlocked and the person can be told who is viewing. It never shows
the login screen or a locked screen on its own. To reach those too, switch
screen capture and input on in the device's configuration (`drm_capture` and
`uinput`): the agent then reads whatever the screen shows, the login screen
included, which is the Linux counterpart of the Windows system mode.

**A headless machine** — enable the agent's virtual-display mode in its
configuration. The machine then has a screen to capture, so *View screen* drops
you into a live console instead of failing.

Set these in the device's configuration rather than through an environment
variable, so they survive a reboot and apply to a daemon started outside
systemd.
:::

## 3 · Reach it when the mesh is what is broken

Screen sharing is the wrong tool when a machine is unreachable *because*
something is broken. Two alternatives ride the agent's existing control
connection rather than the mesh — which is exactly what you want when the mesh
is the problem:

:::cards
- **Remote commands** icon:terminal — Run a command on a trusted device from the dashboard or the CLI. Four independent gates, every attempt audited.
- **[MeshHarbor SSH](/docs/network/ssh/)** icon:shield — A real shell, with no `sshd` and no open port on the target.
:::

Both are **off by default** and stay off until enabled at several independent
levels — see [device policies](/docs/security/device-policies/).

## A caution worth stating

:::danger Unattended access is a standing key to a machine
It is the feature people most often turn on everywhere and then forget. Two
things keep it honest:

- **Grant it per device, not per fleet.** The dashboard makes it a per-device switch for a reason.
- **Read the audit log occasionally.** Every session and every refusal is recorded with who, when and from where. An audit trail nobody reads is a log file, not a control.
:::
