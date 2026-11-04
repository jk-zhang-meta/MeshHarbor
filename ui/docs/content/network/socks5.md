---
title: SOCKS5 proxy
description: Run a local SOCKS5 proxy into a network only one of your machines can see — browse internal sites and reach many hosts without a forward for each one.
tags: [network, socks5, tunnels, proxy, developers]
order: 6
---

A [port forward](/docs/network/tunnels/) is one port to one service. A **SOCKS5
proxy** is one listener that reaches **many** destinations, chosen by the client
at connect time — which is what you want when you are browsing an internal
network rather than talking to a single database.

## Start one

```bash
meshharbor socks5 --agent <agent-id> --local 1080
```

Then point a client at `localhost:1080`:

```bash
curl --socks5-hostname localhost:1080 http://wiki.internal/
```

Or set it as the SOCKS proxy in a browser profile and browse an internal network
as though you were on it.

:::tip Use `--socks5-hostname`, not `--socks5`
The `-hostname` form resolves the name **at the far end**, which is almost always
what you want: `wiki.internal` usually does not resolve on your laptop, only
inside the network you are proxying into. This one flag is the difference
between "it works" and "unknown host".
:::

## Mesh mode

With `--agent`, the proxy exits through **one** machine. **Omit `--agent`** and
you get mesh mode: one proxy that reaches every machine you are allowed to
reach, addressing each by its device id as the SOCKS hostname.

```bash
meshharbor socks5 --local 1080                                  # mesh mode
curl --socks5-hostname localhost:1080 http://<agent-id>:8080/
```

That turns the proxy into a single entry point to your whole private network
rather than to one site of it.

:::tip Omitting a flag is the mode switch
There is no `--mesh` flag. Naming an agent scopes the proxy to it; not naming
one opens it to the whole organization, subject to the same access rules.
:::

## UDP too

UDP association is supported, so DNS and other UDP protocols work through the
proxy rather than falling back to your local resolver — which also keeps internal
names from leaking outward.

## Access control

:::warning The proxy does not widen what you may reach
Every connection through it is authorised individually against the organization's
policy, exactly as a port forward is. A SOCKS5 proxy is a more convenient way to
use the access you already have — never a way to acquire more.
:::

Because each connection is checked separately, a proxy is also the case where
policy is most visible: a browser opens many connections, and any one of them can
be refused on its own.

## Common uses

:::cards
- **Browse internal sites** icon:external — Wikis, dashboards, admin panels that never leave the office network.
- **Reach many hosts at once** icon:network — No need for a forward per service.
- **Scripted access** icon:terminal — Most CLI tools accept a SOCKS proxy through `ALL_PROXY` or a flag.
- **Names that only resolve inside** icon:info — Remote-side resolution makes internal DNS work.
:::

## Stopping it

`Ctrl-C`, or close the terminal. The listener is bound only on your own machine
and disappears with the process.

:::danger Do not bind it to a public interface
A SOCKS5 proxy with no authentication, listening on `0.0.0.0`, is an open relay
into your private network for anything that can reach that port. Leave it on
loopback.
:::
