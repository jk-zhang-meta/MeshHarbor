---
title: Black screen or wallpaper only
description: The session connects and shows nothing — almost always a capture permission or a display-session problem, and almost never a network one.
tags: [troubleshooting, remote-desktop, permissions, capture, macos, windows, linux]
order: 3
---

If the session **connects** and the picture is black, empty or frozen, the
network is working and the problem is capture. Operating systems are famously
unhelpful here: a missing capture grant almost never produces an error.

## Match the symptom

| You see | Almost always |
|---|---|
| Wallpaper, no windows or menu bar | macOS **Screen Recording** grant missing |
| Screen fine, clicks and keys do nothing | macOS **Accessibility** grant, or a Linux keyboard-layout problem |
| Frozen at a lock screen or UAC prompt | Windows agent not in system service mode |
| Completely black, a reconnect fixes it | A capture handle that came up empty |
| Black on a headless Linux box | No session to capture |

## macOS

:::danger Two grants, and macOS reports neither as an error
Open **System Settings → Privacy & Security** and enable **Roomler Daemon**
under both:

- **Screen & System Audio Recording** — without it you get the desktop picture and nothing on it.
- **Accessibility** — without it, keys and clicks are silently dropped.

Then restart the user half:

```bash
launchctl kickstart -k gui/$(id -u)/fans.itachi.meshharbor.agent
```
:::

The menu-bar app names whichever grant is missing and opens the right pane. The
device list also shows *"No screen access"* / *"No input access"* — worth
checking before connecting.

:::warning An update can void the grants
A grant is bound to a specific signed bundle identity. An update that changes it
voids both, and the toggles need re-enabling.
:::

## Windows

:::warning Frozen at the lock screen means the wrong service mode
The lock screen and UAC prompts live on a separate secure desktop that only a
system-mode service can see. If the session works until the machine locks and
then freezes on the last frame, re-install with `-Role daemon-system`.
:::

There is a second, rarer case: a capture handle bound during the transition
between locked and unlocked can return empty frames indefinitely. The agent
detects a stream that has delivered nothing and rebuilds it — so a permanently
black screen that a reconnect fixes was almost certainly this.

## Linux

:::steps
1. **Is there a session to capture?** A root system service has no logged-in session. Use the per-user unit on a desktop, or enable virtual-display mode on a headless machine.
2. **Wayland: is the desktop portal running?** It is started on demand, and if nothing ever triggered it there is no capture source at all. Starting it may not be enough on its own — the portal front-end caches its backend choice at startup and can need a restart after the backend appears.
3. **Input does nothing?** Synthetic key events map through the active keyboard layout. A key not on the detected layout **types nothing and reports success**, which looks like some characters working and others not.
:::

## When it is not a permission

- **A screensaver or a blanked display** on the far end. Move the mouse in the session.
- **A machine with no display attached** and no virtual display configured.
- **A GPU driver that fell over.** The agent's capability probe runs in a separate process specifically so a driver fault cannot take the agent with it — but the machine may still need a reboot.

## Confirming from the far side

```bash
roomler status
```

The agent reports its capture state, so you can tell "no permission" from "no
display" from "working, but the screen really is black" without guessing.
