---
title: Subnet routers
description: Expose a whole LAN through one enrolled machine, so your other devices can reach printers, NAS boxes, hypervisors and appliances that will never run an agent.
tags: [network, subnet-router, routing, lan]
order: 3
---

Some things on a network will never run an agent — a printer, a NAS, a switch's
management interface, a hypervisor, an industrial controller. A **subnet router**
is one enrolled machine that advertises a whole network range on their behalf.

## How it works

:::steps
1. Pick a machine that is **already on the network you want to reach** and is normally on. A small always-on box is ideal.
2. Configure it to advertise the range — for example the office LAN.
3. An administrator **approves** the advertised range in the dashboard.
4. Every other device on the mesh can now reach addresses in that range, routed through the advertising machine.
:::

:::warning Advertising and approving are separate
A machine advertising a range does not get to route it until an admin approves.
"I can reach 10.0.0.0/8, send me everything for it" is a large claim, and it
takes two parties.
:::

## Subnet router or exit node?

They are often confused, and the difference is simple:

| Property | Subnet router | [Exit node](/docs/network/exit-nodes/) |
|---|---|---|
| Routes | **One specific network range** | **All** internet traffic |
| Client-side effect | Extra routes | The default route changes |
| Risk if it goes down | You lose that network | You lose internet access on the client |
| Typical use | Reach the office LAN | Appear to be at the office |

:::tip Prefer a subnet router when you can
It is the smaller, safer tool. Redirecting a device's entire default route is a
much bigger change than adding a route to one range, and it fails in a much more
visible way.
:::

## Overlapping ranges

If two machines advertise the same range, traffic is routed through one of them
— it does not load-balance. Advertise a range from **one** machine unless you
have a specific reason not to.

:::warning Watch out for the ranges you already use
Advertising a range that overlaps with the client's own local network is the
usual cause of "everything broke when I approved this". A laptop on `192.168.1.0/24`
that suddenly routes `192.168.1.0/24` over the mesh has lost its own router.

Pick unambiguous ranges, and prefer advertising the narrowest one that covers
what you actually need.
:::

## Access control still applies

Approving a route makes it *reachable*, not *permitted*. Who may reach which
addresses through it is still governed by the organization's access rules — see
[overlay ACLs](/docs/security/overlay-acls/).

That separation is deliberate: routing and authorisation are different
questions, and collapsing them is how a subnet router becomes an accidental
bridge into a production network.

## Checking it works

From another device:

```bash
meshharbor status     # confirm you have the route
ping <an-address-in-the-range>
```

If the route is present and traffic does not flow, the next suspect is the
advertising machine's own firewall, then the access rules.
