---
title: Files and clipboard
description: Copy text between your machine and a remote one, and transfer files in both directions over the same encrypted peer-to-peer session.
tags: [remote-desktop, files, clipboard, sessions]
order: 5
---

A remote session carries more than pixels. Clipboard contents and file transfers
travel on their own channels **inside the same encrypted peer-to-peer
connection** — they do not take a detour through the server.

## Clipboard

Copy on one side, paste on the other. Text, formatted text and images move in
both directions while the session is open. With auto-sync on, what you copy
follows you without a click; the clipboard buttons on the session toolbar send
or fetch it on demand.

:::warning The clipboard is shared while the session lasts
Anything you copy on either machine becomes available to the other. Be aware of
it before copying a password on the machine you are controlling *from*.
:::

Clipboard sync can be turned off per session if you would rather it did not
follow you.

## File transfer

Drag a file onto the session window to send it to the remote machine, or use the
session toolbar's transfer panel to pull one back.

:::badges
- **Resumable** icon:download — a transfer that is interrupted picks up where it stopped rather than starting again.
- **Direct** icon:network — bytes ride the same peer-to-peer channel as the video, so the server never holds the file.
- **Both directions** icon:copy — send and retrieve within one session.
:::

Progress is shown per transfer, and a transfer continues while you keep working
in the session.

## What the far end sees

Files land in the **Downloads folder of the person signed in at the remote
machine's screen**, unless its owner chose another folder (the desktop app's
**Incoming files** card). A file with the same name as one already there gets a
numbered copy instead of replacing it.

:::tip Nobody at the screen
On a machine whose agent runs as a system service, with nobody signed in at the
screen, a file lands in the service's own folder instead. On Linux, a file sent
while someone is signed in at the screen belongs to them, exactly as if they had
saved it themselves.
:::

## When you want a file path rather than a session

For scripted or repeated movement of files, a session is the wrong tool. Two
better options:

:::cards
- **[SFTP over MeshHarbor SSH](/docs/network/ssh/)** icon:terminal — `scp` and `sftp` work against a node with no `sshd` running. Transfers run as the session's own account, not as the daemon.
- **[Tunnels](/docs/network/tunnels/)** icon:network — forward a file service's port and use whatever client you already have.
:::

## Limits worth knowing

- **A file is not a clipboard item.** Copying a file object in the remote file manager does not carry the file — drag it, or use the transfer panel.
- **An image copied on a Mac, or on a Linux machine under Wayland, waits to be fetched.** A Windows host notices copied images by itself, and so does a Linux desktop on X11 with a per-user install, from agent 0.4.148; elsewhere text still follows you automatically, and the clipboard button brings an image across.
- **A Linux machine whose agent runs as a system service outside any desktop session has no clipboard to share.** Its clipboard buttons stay greyed, with the reason in their tooltip.
- **On macOS**, remote *audio* capture is unavailable, which occasionally surprises people expecting a full session mirror. The receive-audio toggle says so.
- **The Ctrl+Alt+Del button reaches the Windows lock screen only where Windows allows it.** A Windows machine that runs MeshHarbor as a service, and whose "software Secure Attention Sequence" policy lets services send it, gets the real Ctrl+Alt+Del: it reaches the lock and sign-in screens. Elsewhere the button types the three keys. Those reach the programs on the desktop but not the lock or sign-in screen, and the button's tooltip says which condition is missing. On Linux the desktop decides what the keys do: GNOME and KDE offer to log out. A Mac gives the keys no meaning, so the button is not shown there.
- **SFTP against a Windows target** runs as the session's account. On a Windows machine that runs MeshHarbor as a service, a session set to the person signed in at the console transfers files as that person: the transfer starts in their home folder, and an upload belongs to them.
