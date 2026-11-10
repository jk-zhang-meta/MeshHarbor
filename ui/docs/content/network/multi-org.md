---
title: One machine in several organizations
description: Put a single machine in more than one MeshHarbor workspace at once — how identity, addressing and host-global settings behave when organizations overlap.
tags: [network, multi-org, devices, enrollment, advanced]
order: 8
---

A contractor's laptop belongs to their own workspace and their client's. A build
server serves two teams. One machine, several organizations — supported, with
some rules worth knowing before you rely on it.

## One daemon, not several installs

:::danger Do not install a second copy of the agent
It is the intuitive answer and it does not work. The agent owns things that are
**global to the machine**: one network adapter with a fixed name, one local
control socket, one set of routing and firewall state, one updater. A second
install fights the first over all of them.

One agent, several enrollments, is the supported shape.
:::

## Primary and secondary

The **first** enrollment is the primary. Additional organizations are appended
alongside it.

Anything that is necessarily host-global follows the **primary only**:

| Host-global | Why |
|---|---|
| Software updates | There is one binary on the machine |
| Exit-node routing | There is one default route |
| DNS steering | There is one resolver configuration |
| Anything that binds a port | There is one port |

:::warning A secondary organization's admin cannot change host-global settings
That is the point of the distinction. A machine's owner should not have their
update channel or their default route changed by a workspace they merely
collaborate with.
:::

## Addressing

Each organization has its **own address block**, so the machine holds a separate
address per workspace and traffic is demultiplexed by destination. Its
cryptographic identity is **freshly generated per organization** — never copied
between them, so the same machine cannot be correlated across workspaces by its
public key.

## Adding a second organization

Mint an enrollment token in the second workspace and enroll the machine again.

:::danger A restart is required, and nothing tells you
Joining a second organization does **not** start its connection until the agent
restarts. Until then the device looks enrolled in the dashboard and simply never
comes online.

The tell: in the new workspace the device's last-seen time never advances past
its creation time, while the same machine is plainly online elsewhere. If you see
that, restart the agent.
:::

## Checking which organizations are live

```bash
mh org ls    # every organization this machine belongs to
mh status    # connection AND mesh state, per organization
```

:::warning "Connected" and "mesh on" are different claims
An organization can be connected to the control plane with its mesh switched
off, and every surface will otherwise look healthy. `mh status` prints both
on one line for that reason, and an organization with the mesh off is named in
`mh peers` rather than silently omitted.

If a second organization has no mesh, turn it on explicitly and restart:

```bash
mh org overlay <org> netstack   # no adapter: programs reach it through a SOCKS5 port
mh org overlay <org> tun        # a network adapter of its own (a system install)
```

`netstack` needs no privileges and works with any organization's server. The
command prints the SOCKS5 address programs should use (`127.0.0.1:10800`, or the
next free port). It is also what `mh enroll --overlay` picks for a second
organization.
:::

## Platform limits

- **macOS**: each organization gets its own network adapter, as on Windows and Linux (verified on macOS 15). Like the mesh itself on a Mac, it runs in the agent's system half, which runs as root.
- **Exit node** roles are primary-organization only. A second organization can use userspace networking (`netstack`) through its own SOCKS5 port.

## Removing one

Remove the device in that organization's dashboard, or from the machine:

```bash
mh org rm <org>
```

Removing a secondary leaves the primary untouched. Removing the primary is the
bigger operation — the machine's host-global settings belong to it.
