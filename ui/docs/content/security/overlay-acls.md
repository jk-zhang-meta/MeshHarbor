---
title: Network access control
description: Control which machines may reach which machines on the mesh, on which ports and protocols — default-deny, enforced at both ends, and audited.
tags: [security, acl, network, access-control, mesh]
order: 3
---

Being on the mesh should not mean being able to reach everything on it. Network
ACLs decide **which machines may reach which**, on what.

## The shape of a rule

A rule names a **source**, a **destination**, and what may be reached:

| Field | Example |
|---|---|
| Source | A device, a tag, a user, or a group |
| Destination | A device, a tag, or an address range |
| Ports and protocols | `tcp:22`, `tcp:443`, `udp:53`, or all |

Tags are the useful part at any scale: tag machines `prod`, `dev`, `laptop`, and
write rules between tags rather than between machines.

## Three modes — roll out through them, in order

| Mode | Behaviour |
|---|---|
| **Off** | No policy is applied |
| **Warn** | Decisions are evaluated and **logged**, nothing is blocked |
| **Enforce** | Decisions are applied |

:::danger Always go through Warn first
Switch an organization to **Warn**, then read what it reports. Every packet that
*would* have been denied — including port- and protocol-narrowed rules shipped in
`ingress_rules_preview` — is counted in per-peer `rx_would_deny` without being
dropped (older nodes ignore the preview field and never drop traffic either).
Inspect `mh peers`, `mh peers --json` (`debug.rx_would_deny`), `mh why <peer>`,
or the receiving daemon's logs (`overlay acl [warn]: inbound packet WOULD BE DENIED`)
so you can see which rules are wrong before they cost anyone their access.

Warn mode is not ceremony here — it is the recommended rollout path before
flipping to **Enforce**.
:::

## Enforced at both ends

A rule shapes what each machine is even *told about* — a peer you may not reach
is not in your peer list — and is additionally enforced on arrival at the
receiving machine.

That second half matters: it means a machine will not accept traffic it was
never entitled to receive, even if the sender misbehaves. It also covers
**source** and **destination** validity, so a peer cannot claim an address it
does not own or address something outside what it advertises.

## Fail-closed

:::danger An unreadable policy is a denial, not a grant
If the policy cannot be read, the answer is **no**. That sounds obvious and the
opposite is a genuinely easy mistake to make: an implementation that treats "I
could not load the rules" as "no rules apply" grants everything at exactly the
moment something is wrong.
:::

## No policy versus an empty policy

:::warning These are different, and the distinction is kept
**No policy compiled** falls back to the coarse organization-wide scope.
**A policy that permits nothing** denies.

Collapsing them — treating an empty list as "unset" — turns a deliberate denial
into a grant. The same distinction shows up in several places in this product,
and it has been got wrong at least once in each.
:::

## Relays are covered too

The rules gate relay use as well as direct connections, so a machine cannot
reach a peer it is not entitled to by taking a longer path to it.

## Auditing

Every decision is recorded. In warn mode the log is the whole point — read it
before enforcing.

## A worked example

A small organization with laptops, a build server and a production database:

:::steps
1. Tag machines: `laptop`, `build`, `prod`.
2. Allow `laptop → build` on the ports developers actually use.
3. Allow `build → prod` on the database port only.
4. Allow **nothing** from `laptop → prod`. If someone needs the production database, they go through the build host, and that hop is visible.
5. Switch to **Warn**, run real traffic, and check `rx_would_deny` (`mh peers` / `mh peers --json`) and daemon logs on receiving hosts.
6. Switch to **Enforce**.
:::

Step 5 is the one people skip, and it is the one that catches the rule nobody
thought about.
