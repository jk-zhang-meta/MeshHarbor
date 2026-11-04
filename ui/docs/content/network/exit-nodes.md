---
title: Exit nodes
description: Route all of a device's internet traffic through a machine you trust — with split-default routing designed so it can never lock you out of your own box.
tags: [network, exit-nodes, routing, vpn, security]
order: 4
---

An **exit node** is one of your own machines that other devices send their
entire internet traffic through — the classic "look like I am at home while I am
abroad" arrangement, but on hardware you own.

## Setting one up

:::steps
1. **Offer it.** On the machine that should be the exit, enable exit-node mode in its configuration. Offering is not enough on its own.
2. **Approve it.** An administrator approves the device as an exit node in the dashboard. Two parties, deliberately — a device cannot promote itself.
3. **Use it.** On the client, name the exit node you want. All of its traffic — IPv4, IPv6 and DNS — is then routed through that machine, with the IPv6 exceptions below.
:::

## Which machines can be one

| | Linux | Windows | macOS |
|---|---|---|---|
| **Use an exit** | IPv4, IPv6 and DNS | IPv4, IPv6 and DNS | IPv4 and DNS; IPv6 when the Mac's own connection has it, otherwise blocked rather than leaked |
| **Be an exit** | IPv4 and IPv6, from a system (root) install | IPv4 only, and only where Windows has its Hyper-V NAT (Pro, Enterprise); IPv6 through a Windows exit is blocked rather than leaked. Windows **Home** cannot be one | IPv4, and IPv6 where the Mac has a global IPv6 route, from the root half |

A machine that cannot be an exit offers nothing and says why — in
`mh status` and in the dashboard's routes table — rather than offering a
route that every client taking it would lose its internet through.

:::warning Offering and approving are separate on purpose
A device that merely offers to be an exit node is not one. An admin has to
approve it, because "route all your traffic through me" is exactly the claim a
compromised device would like to make.
:::

## The safety property that matters

:::danger Never self-wedge
Rerouting *all* traffic through another machine is one command away from
removing your own access to the box you just typed it on. The implementation is
built around not letting that happen:

- The paths that carry the mesh itself and the control connection are **pinned first**, as explicit exemptions.
- If those exemptions cannot be installed, the change is **withheld entirely** rather than half-applied.
- A guard re-asserts the routes continuously, because other VPN clients are known to reap routes out from underneath.
- On restart, a reconciler heals any leftover routing state from an unclean exit.
:::

Even so, understand what an exit node does to inbound traffic:

:::danger An exit node reroutes replies to *inbound* connections too
That includes the SSH session you may be using to configure it. If you have not
exempted it, enabling an exit node can drop your own shell. Configure exit nodes
from a console you cannot lose, or over the mesh itself, which is exempted.

Do not run an exit-node experiment on a production box that you reach only over
plain SSH.
:::

## DNS

DNS follows the traffic. Queries are answered from the exit node's vantage
point, so name resolution matches where the traffic actually appears — and does
not leak to your local resolver.

## What it is good for

:::cards
- **Travelling** icon:external — Appear at your home or office connection from anywhere.
- **Egress control** icon:shield — Force a fleet's outbound traffic through one auditable point.
- **A known IP** icon:network — Reach a service that allow-lists a specific address, from a machine that has no fixed one.
:::

## What it is not

- **Not anonymity.** Traffic exits from a machine that is yours, with your IP. That is the point, and it is the opposite of hiding.
- **Not a per-application setting.** It is all of the device's traffic, or none.
- **Not a substitute for a subnet router.** If you only want to reach a *specific* network, [subnet routers](/docs/network/subnet-routers/) do that without redirecting everything.

## Turning it off

Remove the setting on the client. The split-default routes are withdrawn and
normal routing returns. If a machine ever comes back from a hard shutdown with
stale routing, the boot reconciler clears it — that case is handled rather than
left to you.
