# How MeshHarbor compares

MeshHarbor is unusual in that it occupies two categories at once: a browser-based
remote desktop, and a WireGuard overlay network — on one agent, one identity and
one server you can host yourself. So the honest comparison is never against a
single product. It is against the *stack* most people assemble.

| You are looking at | Read |
|---|---|
| **Tailscale** — a private mesh between machines | [vs-tailscale.md](vs-tailscale.md) |
| **RustDesk** — open-source remote desktop | [vs-rustdesk.md](vs-rustdesk.md) |
| **TeamViewer / AnyDesk** — commercial remote support | [vs-teamviewer.md](vs-teamviewer.md) |
| **MeshCentral** — self-hosted remote management | [vs-meshcentral.md](vs-meshcentral.md) |
| **NetBird** — open-source mesh with SSO | [vs-netbird.md](vs-netbird.md) |
| **StarDesk** — a gaming-first remote desktop with native apps | [vs-stardesk.md](vs-stardesk.md) |

## The short version

Every one of those products is better than MeshHarbor at the thing it was built
for. They have more years, more users, more platforms and more polish in their
own lane, and each page below says exactly where.

What none of them does is **both lanes on one agent**. If you run Tailscale *and*
RustDesk, you are running two agents, two control planes, two identity systems
and two audit trails on every machine — and the remote-desktop half has no idea
the mesh exists. MeshHarbor is one daemon that is simultaneously the remote-desktop
target, the mesh node, the tunnel exit and the SSH server, so a session, a port
forward and a shell are the same identity, the same policy and the same log.

Whether that consolidation is worth giving up maturity is a real trade, and it
depends on how much you value the seam being gone. These pages are written so
you can decide that honestly rather than be sold on it.

## Our rules for these pages

1. **Every page names things the other product does better**, first, before
   anything about us. A comparison that only flatters its author is marketing,
   and this audience discounts it entirely — correctly.
2. **We describe our own product from the code**, not from a roadmap. If a
   feature is partial, the page says partial.
3. **We do not benchmark competitors.** Numbers produced by a vendor about a
   rival are not evidence, and publishing them would not make them evidence.
4. **Facts go stale.** Everything here was checked on the date at the bottom of
   each page. If something is wrong or out of date,
   [open an issue](https://github.com/jk-zhang-meta/MeshHarbor/issues) — we would
   rather correct it than win an argument on a fact that expired.

## The one-paragraph version of MeshHarbor

One small agent per machine, connecting outbound only. It gives you that
machine's desktop in a browser tab, a stable private address and name on an
encrypted WireGuard mesh, port forwards and a SOCKS5 doorway into whatever that
machine can reach, and an SSH server that binds no port. The coordinating server
introduces peers and enforces policy; traffic is end-to-end encrypted and goes
peer-to-peer whenever a path exists, so the server never sees pixels,
keystrokes, files or tunnelled bytes. The server is AGPL-3.0, everything
installed on a machine is MPL-2.0, and you can host all of it yourself with no
licence key and no device cap — see [`../self-hosting.md`](../self-hosting.md).
