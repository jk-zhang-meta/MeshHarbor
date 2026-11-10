---
title: Troubleshooting
description: Start here when something is not working — a device is offline, a session will not connect, a screen is black, or a call has no video.
tags: [troubleshooting, support, diagnostics]
order: 0
---

Find the symptom. Each page walks the diagnosis in the order the causes actually
occur, most common first.

:::cards
- **[Device is offline or stale](/docs/troubleshooting/device-offline/)** icon:monitor — It was there, and now it is not — or it says "stale".
- **[Cannot connect, or the session is slow](/docs/troubleshooting/cannot-connect/)** icon:network — Sessions fail, or they work but feel sluggish.
- **[Black screen](/docs/troubleshooting/black-screen/)** icon:warning — It connects, and you see nothing, or only wallpaper.
- **[Calls have no video](/docs/troubleshooting/calls-no-media/)** icon:video — Everyone joins, nobody appears.
- **[Install problems](/docs/troubleshooting/install-problems/)** icon:download — It will not install, or it never appears afterwards.
- **[Collecting diagnostics](/docs/troubleshooting/collecting-diagnostics/)** icon:terminal — What to gather before asking for help.
:::

## The two commands worth trying first

```bash
mh status    # this machine: version, organization, connection, mesh address
mh peers     # every peer, and how each one is currently reached
```

Between them they answer most questions before you have finished reading the
symptom page.

## Three things that mislead people

:::warning A device can be "connected" with no mesh at all
Being connected to the control plane and having a private network address are
separate facts. `mh status` prints both on one line for exactly that
reason.
:::

:::warning An empty list is not always "nothing there"
Where a list could mean "none" or "not configured", the product tries to say
which — an organization with the mesh off is named rather than omitted, and an
empty SSH activity log means reporting is off, not that nothing happened.
:::

:::warning A service manager can report a healthy machine as inactive
On Linux, a daemon that is running perfectly can be one systemd does not own —
`systemctl is-active` then says **inactive** while the device is online and
answering. Check `pgrep -x meshharbord` and `mh peers` before believing it,
and do not "restart to fix" on that basis.
:::

## Still stuck?

Gather [diagnostics](/docs/troubleshooting/collecting-diagnostics/) and open an
issue at
[github.com/jk-zhang-meta/MeshHarbor/issues](https://github.com/jk-zhang-meta/MeshHarbor/issues).
Include what you expected, what happened, and the output of `mh status`.
