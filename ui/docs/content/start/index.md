---
title: Get started
description: Create a workspace, install the MeshHarbor agent on Windows, macOS or Linux, and reach your first machine from a browser tab.
tags: [getting-started, install, enrollment]
order: 0
---

Getting to a working setup is three things: **a workspace**, **an agent on a
machine**, and **an enrollment token** that ties the two together.

:::steps
1. **Create a workspace.** Sign up and name your organization — the name labels every device and invite.
2. **Mint an enrollment token.** In the dashboard, go to **Devices → Enroll device**. Tokens are single-use and short-lived.
3. **Install the agent** on the machine you want to reach, pasting the token into the command. One line, or on Windows a graphical installer.
4. **Open the machine** from the Devices list. Its screen appears in a browser tab.
:::

:::tip Start with the machine you are sitting at
It is the fastest way to see the whole loop work, and you can remove the device
afterwards. A browser controlling its own host does produce an infinite mirror
effect — that is expected, not a fault.
:::

## Pick your operating system

The installers differ enough per platform — service model, permissions,
elevation — that each OS has its own page rather than a shared page with
footnotes.

:::cards
- **[Windows](/docs/start/install/windows/)** icon:windows — MSI or one-line PowerShell. Per-user, per-machine, or a SYSTEM service that survives the lock screen.
- **[macOS](/docs/start/install/macos/)** icon:command — A signed `.pkg`. Needs two privacy grants, and the mesh needs a second enrollment.
- **[Linux](/docs/start/install/linux/)** icon:terminal — `.deb` or tarball with a systemd unit. Works headless, in containers, and on cluster nodes.
:::
