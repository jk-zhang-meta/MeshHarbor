---
title: Remote desktop
seoTitle: Remote desktop from any browser, no install — MeshHarbor
description: Remote desktop from any browser — open an enrolled machine as a live screen in a tab, hardware-encoded, end-to-end encrypted and consent-gated.
tags: [remote-desktop, overview, sessions]
hero: remote-desktop.svg
heroAlt: A browser tab showing the live screen of a remote machine, connected directly and encrypted end to end
order: 0
---

Any machine running the agent can be opened as a **live screen in a browser
tab**. The viewing side installs nothing — the controller is a plain browser, on
any operating system, including one that has never heard of MeshHarbor.

:::badges
- **Nothing to install to watch** icon:monitor — only the machine you reach runs an agent.
- **Peer-to-peer and encrypted** icon:shield — pixels and keystrokes never pass through the server in the clear.
- **Works from awkward networks** icon:network — hotel Wi-Fi, NAT, corporate firewalls and full-tunnel VPNs.
:::

## How a session works

:::steps
1. You click **View screen**. The server checks you are allowed, and introduces the two ends to each other.
2. The machine asks whoever is sitting at it — unless it is configured for unattended access.
3. The two ends negotiate the **fastest path that works**: local network first, then a direct internet path, then hole-punching, then a relay.
4. Video, input, clipboard and file transfer flow over that path. The server is out of the way and never sees the contents.
:::

The last point is the one that matters most for privacy: the server's role ends
once the two ends can talk. It coordinates; it is never a data path.

## What you can do in a session

:::cards
- **[Your first session](/docs/remote-desktop/first-session/)** icon:monitor — Multiple monitors, quality control, keyboard handling and what the on-screen indicators mean.
- **[Unattended access](/docs/remote-desktop/unattended-access/)** icon:flag — Reach your own machines without anyone approving at the far end.
- **[Consent](/docs/remote-desktop/consent/)** icon:shield — Who gets asked, on which surface, and what happens when nobody answers.
- **[Codecs and performance](/docs/remote-desktop/codecs-and-performance/)** icon:video — Hardware encoders per platform, and what to change when it feels slow.
- **[Files and clipboard](/docs/remote-desktop/files-and-clipboard/)** icon:copy — Move files and clipboard contents in both directions.
- **[Screen recording](/docs/remote-desktop/recording/)** icon:video — Record your own screen or a remote one in full quality, then cut it, speed it up and add music.
- **[Per-OS permissions](/docs/remote-desktop/per-os-permissions/)** icon:wrench — What each operating system makes you grant before capture works.
:::

## Requirements

| Side | Needs |
|---|---|
| **Viewer** | A current browser: Chrome, Edge or another Chromium browser works best; Safari and Firefox work too. Nothing installed. |
| **Target** | The agent, and whatever screen-capture permission the OS demands. |

Chromium browsers are the recommendation: the low-latency decode path the viewer
relies on has had the most testing there. Safari and Firefox run the viewer too,
with less testing so far.
