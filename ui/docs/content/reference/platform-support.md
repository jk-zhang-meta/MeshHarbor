---
title: Platform support
seoTitle: Platform support — Windows, Linux and macOS
description: What Roomler does on Windows, Linux and macOS, feature by feature, and the reason wherever an operating system cannot do something.
tags: [reference, platforms, windows, linux, macos]
order: 5
---

Roomler is one product on three operating systems. When a feature works on one
of them, it works on the other two, or the device tells you why it cannot:
on the control itself, in `roomler status`, and in the dashboard. A control
that is greyed out always carries the device's own reason.

:::badges
- **✅ Works** icon:check — on that operating system, today.
- **🟡 In part** icon:info — the table says which part.
- **❌ Not yet** icon:warning — the OS could do it; Roomler does not yet.
- **⛔ Ruled out** icon:danger — the OS itself prevents it. The reason is below.
:::

These tables describe agent 0.4.148; a row that names 0.4.149 is coming in the
next release. The engineering record behind them, with
the code each verdict comes from, is
[`docs/platform-support.md`](https://github.com/gjovanov/roomler-ai/blob/master/docs/platform-support.md).

## Which install does what

Most of this page follows from one question: does the agent run as the
machine, or as you? Joining the private network on a real network adapter
needs the machine's own identity on every OS. Showing your desktop needs a way
into your session.

| OS | Install | Runs as | Gives you |
|---|---|---|---|
| Windows | **Machine — system** | a service, with SYSTEM in your session | your desktop, the lock and sign-in screens, the private network |
| Windows | **Machine — attended** | a service, with you in your session | your desktop, the private network |
| Windows | **Per user** | you, from sign-in | your desktop |
| Linux | **System** (`--system`) | root, from boot | the private network; your GNOME or KDE desktop while you are at it and it is unlocked |
| Linux | **Per user** (the default) | you | your desktop |
| macOS | the **per-user half** (the default) | you, in your login session | your desktop |
| macOS | the **root half** (`--daemon-token`) | root, from boot | the private network |

A Mac needs both halves for both, and shows up as two devices.

:::tip No admin rights? You can still join the network
An install that runs as you cannot create a network adapter, but it can join
the network in **netstack mode**: set `MESHHARBORD_OVERLAY_NETSTACK_SOCKS` to a
free port for the agent, and your apps reach the other devices through that
local SOCKS5 port. Roomler SSH into this machine still works. A second
organization chooses it with `roomler org overlay <org> netstack`
([multi-org](/docs/network/multi-org/)).
:::

## Remote desktop

| Feature | Windows | Linux | macOS |
|---|---|---|---|
| Your desktop, with a system install and nothing configured | ✅ | 🟡 GNOME and KDE, while your session is unlocked and you can be told who is viewing | 🟡 an opt-in |
| The lock screen and sign-in screen, nobody signed in | ✅ Machine — system | 🟡 only when you switch screen capture on yourself | ⛔ |
| The computer's sound | ✅ | ✅ | ❌ |
| Recording with sound | ✅ | ✅ | 🟡 picture only |
| Ctrl+Alt+Del | ✅ the real one, from a Machine — system install where policy allows | ⛔ sent as ordinary keys, which GNOME and KDE use to log out | ⛔ hidden: it means nothing on a Mac |
| An approval panel on the host | ✅ | ✅ X11 · ⛔ Wayland: the desktop app asks | ❌ the desktop app asks |
| "The host is locked" before you connect | ✅ | ❌ | ✅ from agent 0.4.150 |
| "The host is locked" while you are connected | ✅ | ✅ | ✅ from agent 0.4.150 |
| The host's cursor, drawn by your browser | ✅ | ✅ system installs, and X11 desktops from agent 0.4.147; a per-user Wayland desktop draws it into the picture | ❌ the cursor is part of the picture |
| Remote Apps | ✅ | ✅ X11 · 🟡 Wayland: Xwayland windows | ❌ |
| Show and switch the keyboard layout | ✅ | ✅ X11 desktops with a per-user install, from agent 0.4.148; on GNOME the layout is shown, and you switch it with GNOME's own shortcut (Super+Space) · ❌ Wayland desktops and system installs | ❌ |
| Typing text on a non-US layout | ✅ | ✅ on any layout from agent 0.4.147; before it, a system install types only on a US layout, and refuses rather than mistype | ✅ |
| Match the remote display to your window | ✅ | ✅ X11 desktops with one screen and a per-user install, from agent 0.4.148, and the agent's own virtual desktop · ❌ Wayland desktops, system installs, several screens | ❌ |
| Clipboard: text, formatted text and images | ✅ | ✅ per-user · ❌ a system install | ✅ |
| A copied image arrives by itself | ✅ | ✅ X11 desktops with a per-user install, from agent 0.4.148 · ❌ Wayland desktops and system installs: on request | ❌ on request |
| An idle desktop costs little CPU | ✅ | ✅ | ❌ |
| Privacy mode (the person at the computer sees a notice, not the desktop) | ✅ Windows 10 2004 and later | ❌ | ⛔ |
| Lock the computer when the last session ends | ✅ | ✅ | ❌ |

The same on all three: the main display, high-DPI screens, hardware video
encoding (on a Mac, H.264 and HEVC), the relative mouse for 3D apps and games,
touch controls, keep-busy, recording, file transfer, and the
[consent](/docs/remote-desktop/consent/) flow. The permissions each OS asks for
are on [per-OS permissions](/docs/remote-desktop/per-os-permissions/).

## Private network

| Feature | Windows | Linux | macOS |
|---|---|---|---|
| Join the network on a real adapter | ✅ Machine installs | ✅ system install | ✅ the root half |
| One adapter per organization | ✅ | ✅ | ✅ |
| Use an [exit node](/docs/network/exit-nodes/) | ✅ | ✅ | ✅ IPv6 when your connection has it, otherwise blocked rather than leaked |
| Be an exit node or a [subnet router](/docs/network/subnet-routers/), IPv4 | 🟡 needs Windows' Hyper-V; never on Home | ✅ | ✅ the root half |
| Be an exit node, IPv6 | ⛔ | ✅ | ✅ where the Mac has a global IPv6 route |
| Device names resolve on the computer ([MagicDNS](/docs/network/addresses-and-magicdns/)) | ✅ | 🟡 with systemd-resolved; when nothing asks it, `roomler status` says so | ✅ |
| Your firewall lets the network in | ✅ a Machine install adds its own rule | 🟡 yours to open; `roomler status` names the zone | ❌ yours to open |

The same on all three: direct and relayed connections, the relay floor over
443, [tunnels](/docs/network/tunnels/), SOCKS5, access rules, key rotation and
[ephemeral devices](/docs/network/ephemeral-nodes/).

## SSH and remote commands

| Feature | Windows | Linux | macOS |
|---|---|---|---|
| Run as the machine | 🟡 SYSTEM on a Machine — system install, or once an admin anchors the device | ✅ root | ✅ root, on the root half |
| Run as the person at the screen | 🟡 where SYSTEM serves the session | ✅ | ✅ |
| Run as a named account | ⛔ | ✅ | ✅ |
| SFTP and `scp` as the person at the screen | 🟡 where OpenSSH's `sftp-server` is installed | ✅ | ✅ |
| A session starts in your home folder | ✅ | ✅ | ✅ |

More on [Roomler SSH](/docs/network/ssh/).

## On the computer itself

| Feature | Windows | Linux | macOS |
|---|---|---|---|
| The desktop app | ✅ | 🟡 a `.deb` and an `.rpm`, for x86_64 and arm64; nothing for a computer with neither package manager, such as Arch | ✅ |
| The computer stays awake during a session | ✅ | ✅ | ✅ except a closed laptop with no external display |
| A received file lands in your own Downloads | ✅ | ✅ | ✅ |
| The setup wizard installs the agent | ✅ | ❌ use the one-line install | ❌ use the one-line install |

## Installs and updates

| Feature | Windows | Linux | macOS |
|---|---|---|---|
| Updates itself, per-user installs included | ✅ | ✅ | ✅ |
| Checks a download is the version it was offered as | ✅ | ✅ | ✅ |
| One-command uninstall | ✅ | ✅ | ✅ |
| An ephemeral device removes itself when it stops | ✅ | ✅ | ✅ |
| The tunnel client (`roomler self-update`) updates itself | ✅ | ✅ from the next tunnel release | ✅ from the next tunnel release |
| Processors the agent runs on | 🟡 x64; ❌ ARM | ✅ x86_64 and arm64 | 🟡 Apple silicon; ❌ Intel |
| Hardware video encoding on Linux ARM | — | ❌ | — |
| The tunnel client and the wizard on Linux ARM | — | ✅ from 0.4.149: the wizard with the agent release, the tunnel client with the first tunnel release from then on | — |

## Where the operating system rules it out

| Feature | OS | Why |
|---|---|---|
| Ctrl+Alt+Del | Linux | The desktop decides what the keys do, and GNOME and KDE log you out. The button sends the keys and says so |
| Ctrl+Alt+Del | macOS | The keys have no meaning on a Mac, so the button is hidden |
| An approval panel on a Wayland desktop | Linux | GNOME and KDE let no ordinary app draw over the desktop. The desktop app asks instead |
| The lock screen and sign-in screen | macOS | Capture needs a signed-in session. Reaching the login window would take a different kind of install, managed through MDM |
| Privacy mode | macOS | Since macOS 15, no app can keep a window out of screen capture, so the notice would be streamed too |
| Staying awake with the lid closed | macOS | A laptop with no external display sleeps when the lid closes, whatever any app asks |
| Being an IPv6 exit node | Windows | Windows' built-in NAT has no IPv6. IPv6 through a Windows exit is blocked, never leaked |
| Running as a named account | Windows | Windows cannot start a program as another account without that account's password |
