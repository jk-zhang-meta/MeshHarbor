---
title: Addresses and MagicDNS
description: How each machine gets a stable private address on the mesh, how names work instead of numbers, and what happens to an address when a device is removed.
tags: [network, mesh, magicdns, addressing, devices]
order: 1
---

Every machine on the mesh gets a **private address that does not change** when
the machine moves between networks, plus a **name** you can use instead.

## Addresses

Addresses are allocated per organization from a private range, and they are
**leases** rather than properties of the hardware: a machine holds one for as
long as it is enrolled.

```bash
mh status    # your own address
mh peers     # everyone else's
```

:::badges
- **Stable across networks** icon:network — the same address at home, in the office, on hotel Wi-Fi.
- **Private by construction** icon:shield — not routable from the internet; only your own machines can reach it.
- **One per organization** icon:check — each workspace has its own address space.
:::

## Names, not numbers

Each device also gets a **name** on the mesh, so you can use `ssh dev-box` or
`http://build-server:8080` instead of memorising an address. Names come from the
device name you chose at enrollment and can be changed later in the dashboard.

:::tip A rename propagates
Renaming a device in the dashboard updates the name across the mesh; you do not
need to touch anything on the machines themselves.
:::

## Every organization has its own address space

Organizations are carved into **separate, non-overlapping** address blocks, so
two workspaces can never hand out the same address to different machines.

:::warning This was not always true, and the failure mode was subtle
Address carving was originally opt-in, and an organization that never opted in
shared one big range with everyone else — so two workspaces could genuinely hold
the *same* address. It is on by default now, and every organization has a
disjoint block.

The lesson is worth carrying: **a default that has to be remembered is not a
default.**
:::

## What happens when a device is removed

Removing a device does three things atomically: it revokes the credential, tells
every other node to forget the peer, and returns the address to the pool for the
**next** joiner.

:::danger A removed device never gets its old address back
Re-enrolling the same machine gives it a **fresh** address. Anything pinned to
the old one — a bookmark, a firewall rule, a config file, a script — needs
updating.

This is deliberate. "Evict" means *force a new lease*, not *ban*: a machine that
is still authorised can rejoin immediately, just at a different address. And
device rows are kept as a record of who held a name and an address, rather than
being deleted outright.
:::

## Address exhaustion

Each organization's block is large enough for well over a thousand devices.
Blocks can be grown without renumbering existing machines, so running out is an
administrative event rather than a migration.

## Seeing the whole picture

`mh peers` is the authoritative view from a machine's own perspective: who
it can see, at what address, over which path.

:::warning An empty list is not always "no peers"
If an organization has the mesh switched off, it is **named explicitly** rather
than omitted — because a silently-absent organization is indistinguishable from
one whose peers are all offline, and that ambiguity has cost real debugging
time.
:::
