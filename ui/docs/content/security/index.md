---
title: Security & access control
description: How MeshHarbor decides who may reach what — end-to-end encryption, roles and permissions, network ACLs, device-held gates, consent and audit.
tags: [security, access-control, overview, permissions, audit]
hero: acl.svg
heroAlt: Layered access control gating who may reach which machine, with every decision recorded
order: 0
---

Access control here is **layered and default-deny**, and the layers are owned by
different parties on purpose: an organization, an administrator, a user and the
machine itself each hold a gate, and **any one of them refuses**.

:::cards
- **[Security model](/docs/security/security-model/)** icon:shield — Encryption, what the server can see, and where trust actually sits.
- **[Users, roles and permissions](/docs/security/users-roles-permissions/)** icon:check — Who can do what inside an organization.
- **[Network ACLs](/docs/security/overlay-acls/)** icon:network — Which machines may reach which machines, and on what.
- **[Device policies](/docs/security/device-policies/)** icon:monitor — Per-machine gates for remote commands, SSH and relaying.
- **[Consent and audit](/docs/security/consent-and-audit/)** icon:book — Who gets asked, and what is recorded afterwards.
- **[Signed releases](/docs/security/signed-releases/)** icon:download — How to know the software you installed is ours.
- **[Self-host hardening](/docs/security/self-host-hardening/)** icon:terminal — What to get right when you run it yourself.
:::

## The one idea worth taking away

:::danger The last gate is always held by the machine
For the most powerful features — remote command execution, SSH, acting as a
relay — the final decision lives in the machine's own configuration, and **the
server cannot write it**.

That is not redundancy. It is the property that makes the whole chain worth
something: if the control plane were compromised, every server-side gate would
fall at once. A gate the server cannot open is the only one that survives that.
:::

The consequence is a real trade-off, stated honestly: turning these features on
requires touching the machine, or explicitly opting that machine in to being
remotely configurable. That is a cost, and it is deliberate.

## Default-deny, everywhere it counts

| Surface | Default |
|---|---|
| Remote commands | Off, at four independent levels |
| SSH | Off, at four independent levels |
| Acting as a relay for others | Off |
| Being an exit node | Off, and needs a separate admin approval |
| Consent for a remote session | **Ask** — an absent setting means ask, not allow |
| SSH port forwarding on a device | Nowhere, until a destination is named |

:::warning An empty list means "nothing", not "everything"
Where the product distinguishes *no policy configured* from *a policy that
permits nothing*, it keeps them distinct. Collapsing the two is how an
access-control system silently becomes permissive.
:::
