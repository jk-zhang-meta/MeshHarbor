# Roomler vs Tailscale

Tailscale is the reason most people know what an overlay mesh is. Roomler's
networking pillar is deliberately built to the same shape — a WireGuard mesh with
stable addresses, DNS names, subnet routers and exit nodes — because that shape
is right, and pretending otherwise would waste your time.

## What Tailscale does better

Be clear-eyed about this list before reading any further.

- **Maturity and scale.** Years of production use across an enormous fleet, with
  the operational record that only time produces. Roomler is young.
- **Platform coverage.** iOS, Android, Synology, QNAP, routers, embedded — a
  reach Roomler does not have. Roomler's agent is Windows, Linux and macOS, and
  its browser side is Chromium-first.
- **Funnel.** Publishing a service to the public internet from a node is a
  first-class Tailscale feature. Roomler has no equivalent — its tunnels reach
  *into* your network from your own devices, and there is no public-ingress
  story today. If you use Funnel or `serve`, that is a real gap.
- **Identity integrations.** SSO, SCIM provisioning, device posture, and the
  breadth of IdP support an enterprise procurement process asks for.
- **Ecosystem.** A large community, a lot of published recipes, and integrations
  with things you already run.

If your problem is purely "I want a private network between my machines", and
none of the differences below matter to you, Tailscale is an easy recommendation
and you should use it.

## Where Roomler differs

**Remote desktop is not an add-on; it is the other half of the product.** With
Tailscale you get a network, and then you still install something to actually see
a screen — RustDesk, RDP, VNC, TeamViewer — with its own agent, control plane and
permissions. In Roomler the same daemon that is the mesh node is also the remote
desktop target. Opening a machine's screen and forwarding its Postgres port are
the same identity, the same ACL system and the same audit trail.

**The whole control plane is open source, and self-hosting is a supported first
path, not a reimplementation.** Tailscale's clients are open source; the
coordination server is not, which is why Headscale exists as a separate
community project. Roomler's server is AGPL-3.0 and the self-hosted stack is
[one compose file](../self-hosting.md) — the same code that runs the hosted
service, with no device cap and no licence key.

**SSH with no `sshd` and no bound port.** Tailscale SSH is excellent and does the
same job on Linux. Roomler's implementation intercepts TCP for its own overlay
address below the OS and terminates it in an in-process netstack, which means it
also works on **Windows**, and on hosts where port 22 is already taken or where
an EDR agent kills `sshd` as a service. See [`../meshharbor-ssh.md`](../meshharbor-ssh.md).

**Where it runs.** The hosted control plane is operated by an EU company (G ROX
EOOD, Bulgaria) on its own hardware rather than on a hyperscaler. If jurisdiction
is a procurement question for you, that is a different answer from the usual one
— and self-hosting removes the question entirely.

**Chat, rooms and video calls are included** on the same server and accounts.
Whether that is a feature or noise depends entirely on whether you wanted it.

## Side by side

| | Roomler | Tailscale |
|---|---|---|
| WireGuard mesh, stable IPs | yes | yes |
| DNS names for nodes | MagicDNS | MagicDNS |
| Subnet routers, exit nodes | yes | yes |
| NAT traversal + relay fallback | LAN → direct → hole-punch → TURN → DERP over :443 | DERP |
| SSH without `sshd` | yes, incl. Windows | yes, Linux-family |
| Public ingress (Funnel) | **no** | yes |
| Remote desktop | **built in, browser-based** | not in scope |
| Tunnels / SOCKS5 to a node's network | yes | via subnet routes |
| Control plane open source | yes (AGPL-3.0) | no (Headscale is third-party) |
| Self-host | one compose file, unlimited devices | Headscale, community-maintained |
| Mobile clients | **no** | yes |
| SSO / SCIM | **not yet** | yes |
| Chat / video conferencing | included | not in scope |
| Hosted free plan | 10 users, 100 devices, MagicDNS; **commercial use allowed** | 6 users, unlimited personal devices + 50 tagged resources; **non-commercial** |
| Hosted paid plans | per seat: $8 / €8 a month (Pro), $16 / €16 (Business); a year is two months free | per seat: $8 a month (Standard), $18 (Premium) |

## Choosing

- **Use Tailscale** if you need mobile, Funnel, SSO, or maximum maturity, and
  you are happy to run a separate remote-desktop product beside it.
- **Use Roomler** if you want the mesh *and* the remote desktop from one agent
  with one policy model, or if a fully open, self-hostable control plane matters
  more to you than platform breadth.
- **Both are WireGuard.** Neither locks up your data plane; migrating either
  direction means re-enrolling devices, not re-architecting.

---

*Checked 2026-08-29 against Roomler's own source and Tailscale's public
documentation; the plan rows on 2026-10-19 against tailscale.com/pricing
(FR-115). If anything here is wrong or has aged,
[open an issue](https://github.com/gjovanov/roomler-ai/issues) — we would rather
fix it than win on a stale fact.*
