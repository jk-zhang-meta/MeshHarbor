---
title: What the server sees
description: Precisely what the MeshHarbor control plane can and cannot observe — including the one feature that is deliberately an exception to the rule.
tags: [architecture, security, privacy, design]
order: 4
---

Trust claims are worth stating as topology, not as policy. What follows is what
the server is *structurally capable of seeing* — which is a stronger statement
than what it is configured to do.

## What the server holds

| It has | Because |
|---|---|
| Accounts, organizations, memberships | It authenticates you |
| Device rows, names, addresses, versions | It is the registry |
| Permissions and policies | It is the decision point |
| **Audit records** — who asked for what, when, and the outcome | That is the whole point of them |
| Chat messages, rooms, and uploaded files | It is a chat product; these live there |
| Presence and connection metadata | It routes and notifies |

## What the server does not hold

:::badges
- **No session video** icon:monitor — the pixel stream is never recorded, and the server is not in the path to record it.
- **No keystrokes** icon:terminal — input travels on the same peer-to-peer channel as the video.
- **No tunnel contents** icon:network — a forwarded connection is between your two machines.
- **No SSH bytes** icon:shield — including the commands you typed and their output.
- **No mesh traffic** icon:check — whatever you send between machines is between them.
:::

## Why, structurally

The server's job for the data planes ends once two machines can find each other.
After that it is not on the path, so there is nothing for it to log even in
principle.

When no direct path exists, traffic falls back to a **relay** — and a relay
forwards ciphertext it cannot decrypt. Adding a relay hop changes performance,
never visibility.

:::tip This is why the last gate on a machine is device-held
Several settings — whether SSH is enabled, whether remote commands are allowed,
whether the machine accepts remote configuration at all — live on the machine
and **cannot be written by the server**. That is not belt-and-braces; it is what
makes them meaningful if the control plane is ever compromised.
:::

## The exception, stated plainly

:::danger Conference media passes through the server
Video calls use a selective forwarding unit: each participant sends their stream
to the server, which forwards it to the others. The server therefore **does**
handle call media, because that is what a forwarding unit is.

It is not recorded unless someone in the call presses record. But if your threat
model distinguishes "handled" from "not handled", conferencing is on the other
side of that line from every other feature.
:::

## Self-hosting

Self-hosting collapses the distinction: the server is yours, so "what the server
sees" becomes "what your own machine sees". Nothing is held back from a
self-hosted deployment — see [self-hosting](/docs/start/self-hosting/).

## Verifying rather than believing

- **Audit logs** record every session, command and SSH request, including refusals with their reason.
- **Device-held gates** cannot be flipped by us.
- **The code is public.** The server is AGPL-3.0 and the agent is MPL-2.0, so the claims on this page are checkable rather than promised.

See [security model](/docs/security/security-model/) for the full picture.
