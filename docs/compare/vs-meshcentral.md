# MeshHarbor vs MeshCentral

MeshCentral is the closest thing to a direct predecessor: self-hosted, agent-based,
browser-based remote control of a fleet, free and open source (Apache-2.0). If
you already run it and it works, this page is unlikely to move you, and that is
a reasonable outcome.

## What MeshCentral does better

- **Breadth of fleet management.** Hardware inventory, power control, Intel AMT
  / out-of-band management, software deployment, terminal, file manager, device
  groups — a genuine RMM surface. MeshHarbor's fleet features are narrower:
  enrolment, policy, remote command execution, audit, observability.
- **Maturity.** More than a decade of production use, an enormous documentation
  corpus, and a long tail of solved deployment problems.
- **Protocol breadth.** RDP, VNC and SSH relaying through the web UI, so it
  reaches devices that will never run its agent.
- **Apache-2.0 throughout**, with no split and no commercial edition to reason
  about. If any copyleft at all is a problem for you, that is simpler than
  MeshHarbor's AGPL server.
- **Runs on very little.** A Node.js app and a database; it will live happily on
  hardware where MeshHarbor's stack would not.

## Where MeshHarbor differs

**A private network, not just a management channel.** MeshCentral relays a
session to a device. MeshHarbor puts the device on a WireGuard mesh: a stable
private address, a DNS name, direct peer-to-peer paths between the devices
*themselves*, port forwards, a SOCKS5 doorway, exit nodes, and SSH with no
`sshd`. Two enrolled machines can talk to each other without the server in the
path at all — which MeshCentral's hub-and-spoke model does not do.

**The server is not in the data path.** MeshCentral relays sessions through the
server by design. MeshHarbor's sessions are peer-to-peer WebRTC, end-to-end
encrypted, falling back to a relay that forwards ciphertext only when no direct
path can be punched. That is a bandwidth-and-cost difference at fleet scale and a
trust difference at any scale.

**The remote-desktop path is built for interactive work.** Hardware encoding
(NVENC / Quick Sync / AMF / Media Foundation) with a probe-and-rollback cascade,
H.264/HEVC/AV1/VP9, and a WebCodecs rendering path that bypasses the browser's
jitter buffer. MeshCentral's remote desktop is capable but is not chasing a
low-latency interactive budget.

**Modern interface and identity.** OAuth sign-in across five providers, roles
and a permission bitfield, multi-tenant organizations, invitations, and a UI
built this decade. This is subjective, and MeshCentral users are often
unbothered by it — but it is the most common first reaction.

**Chat, rooms and video conferencing** on the same server and accounts.

## Side by side

| | MeshHarbor | MeshCentral |
|---|---|---|
| Self-hosted, free, unlimited devices | yes | yes |
| Browser-based remote desktop | yes | yes |
| Session path | **peer-to-peer, E2E encrypted** | relayed through the server |
| Hardware-encoded video | yes, with cascade + fallback | basic |
| WireGuard mesh between devices | **yes** | no |
| Port forwards / SOCKS5 / exit nodes | **yes** | limited |
| SSH without `sshd` | yes | relays to an existing sshd |
| RDP / VNC / AMT relaying | **no** | yes |
| Hardware inventory, power control | **no** | yes |
| Intel AMT / out-of-band | **no** | yes |
| Mobile agent | no | limited |
| Licence | AGPL server + MPL agent | Apache-2.0 |
| Chat / video conferencing | included | not in scope |

## Choosing

- **Use MeshCentral** if you need RMM breadth — inventory, AMT, power control,
  RDP/VNC relaying to devices that cannot run an agent — or if a permissive
  licence throughout is a requirement.
- **Use MeshHarbor** if you want the devices networked to *each other* rather than
  only reachable from a console, if session traffic staying off your server
  matters, or if remote-desktop responsiveness is the thing you are unhappy with.
- **Honest framing:** MeshCentral is a management platform that includes remote
  desktop. MeshHarbor is a remote-desktop-and-network product that includes fleet
  management. Pick by which noun you actually need.

---

*Checked 2026-08-29 against MeshHarbor's own source and MeshCentral's public
documentation. If anything here is wrong or has aged,
[open an issue](https://github.com/jk-zhang-meta/MeshHarbor/issues) — we would rather
fix it than win on a stale fact.*
