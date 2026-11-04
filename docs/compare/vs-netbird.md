# Roomler vs NetBird

NetBird is the open-source overlay mesh that has done the best job of making
self-hosting a first-class path rather than a reverse-engineered afterthought.
On the networking pillar it is the closest comparison to Roomler, and it is a
good product.

## What NetBird does better

- **Maturity on the mesh.** Shipping steadily since 2022, with a real team, a
  large user base, and the operational record that follows.
- **Identity.** SSO and IdP integration (Okta, Entra, Keycloak, Google and
  others), groups, and policy built around them. Roomler has OAuth sign-in but
  no SSO/SCIM provisioning, and that is a genuine gap for an org of any size.
- **Platform coverage.** Clients across more platforms, including mobile, plus a
  Kubernetes operator and container-friendly deployment patterns.
- **Self-hosting polish.** Official UI, coordinator and clients as one
  supported open-source stack, with a well-worn install path.
- **Ecosystem and documentation.** More recipes, more integrations, more people
  who have hit your problem first.

If your requirement is an open-source Tailscale replacement with SSO, NetBird is
the direct answer and you should evaluate it seriously.

## Where Roomler differs

**Remote desktop is in the same daemon.** This is the whole difference. NetBird
gives you the network; seeing a screen is then a separate product with its own
agent, control plane and permissions. Roomler's daemon is simultaneously the
mesh node, the remote-desktop target, the tunnel exit and the SSH server — so a
desktop session, a port forward and a shell share one enrolment, one ACL model
and one audit trail.

**Where the hosted control plane runs.** Both are European: NetBird is
Berlin-based, Roomler is operated by G ROX EOOD (Bulgaria). The difference is the
substrate — Roomler's hosted control plane runs on hardware the company owns and
operates, not on a hyperscaler. Whether that distinction matters is your call,
but it is a question that gets asked, and the answers differ.

**Carrier selection is measured, not assumed.** The path cascade is LAN →
direct-public → NAT hole-punch → TURN relay → DERP over TLS :443, chosen by a
server verdict over measured capability vectors, with continuous re-attempt to
upgrade a session that fell back. There is also a userspace mode
(`overlay-netstack`) that provides the mesh through a loopback SOCKS5 front with
**no TUN device and no routing changes** — for hosts where you have no admin
rights on the network stack, or where a corporate VPN client owns the routing
table. See [`../overlay-nat-traversal.md`](../overlay-nat-traversal.md).

**SSH that works on Windows.** Roomler intercepts TCP for its own overlay
address below the OS and terminates it in an in-process netstack, so there is no
`sshd` to install and no port bound — on Windows as well as Unix, and on hosts
where port 22 is already taken or an EDR agent kills `sshd` as a service. See
[`../meshharbor-ssh.md`](../meshharbor-ssh.md).

**Chat, rooms and video conferencing** on the same server and accounts.

## Side by side

| | Roomler | NetBird |
|---|---|---|
| WireGuard mesh, stable IPs, DNS names | yes | yes |
| Subnet routers, exit nodes | yes | yes |
| ACL policy engine | yes (`off` / `warn` / `enforce`) | yes |
| Self-host the full stack | yes, one compose file | yes |
| SSO / IdP integration | **no** | yes |
| Mobile clients | **no** | yes |
| Kubernetes operator | **no** | yes |
| Userspace mode, no TUN, no admin rights | **yes** | limited |
| SSH without `sshd`, incl. Windows | yes | Unix-family |
| **Remote desktop, browser-based** | **yes** | not in scope |
| Tunnels / SOCKS5 into a node's network | yes | via routes |
| Chat / video conferencing | included | not in scope |
| Licence | AGPL server + MPL agent | AGPL |

## Choosing

- **Use NetBird** if you need SSO, mobile, a Kubernetes operator, or the more
  mature mesh, and remote desktop is somebody else's problem.
- **Use Roomler** if you want the mesh *and* the remote desktop on one agent with
  one policy model — or if you have hosts where you cannot own the routing table
  and need the userspace path.
- **Both are WireGuard and both are self-hostable.** Neither traps your data
  plane; evaluating one does not cost you the other.

---

*Checked 2026-08-29 against Roomler's own source and NetBird's public
documentation. If anything here is wrong or has aged,
[open an issue](https://github.com/gjovanov/roomler-ai/issues) — we would rather
fix it than win on a stale fact.*
