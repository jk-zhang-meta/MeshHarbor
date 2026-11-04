---
title: Frequently asked questions
description: Short answers about MeshHarbor — what it is, what it costs, whether it can see your screen, how it compares to Tailscale and RustDesk, and how to self-host it.
tags: [faq, overview, getting-started, security, self-hosting, pricing]
faq: true
order: 0
---

## What is MeshHarbor?

MeshHarbor is three products on one agent: a browser-based remote desktop, a private
WireGuard-style mesh network between your machines, and team chat with video
calls. You install one agent per machine and use everything from a browser tab.
It runs on Windows, macOS and Linux, and you can host the whole thing yourself.

## Do I need to install anything to view a remote screen?

No. The viewing side is a plain browser with nothing installed (Chrome, Edge or
another Chromium browser works best; Safari and Firefox work too). Only the
machine you are reaching runs an agent.

## Can MeshHarbor see my screen or my keystrokes?

No. Remote-desktop video and input travel directly between your browser and the
machine, encrypted end to end. When no direct path exists the traffic falls back
through a relay, and the relay forwards ciphertext it cannot read. The pixel
stream is never recorded.

The one exception is video conferencing: a call's media passes through the
server, because a multi-party call needs a forwarding unit. No other feature
works that way.

## Is it free?

There is a free plan for up to 10 users and 100 devices, and commercial use is
allowed on it: a business can run on the free plan, and nothing tries to detect
one. The private network, remote desktop, tunnels, chat and calls are all
included. Paid plans are billed per user; they raise the limits and add features
like exit nodes, and the [pricing page](/pricing) shows the billing periods and
currencies on offer. Self-hosting has no plan limits at all.

## Can I host it myself?

Yes, and it is a first-class path rather than a stripped-down one. One compose
file and published container images; on a clean machine the documented path
answered in 32 seconds over a data-centre connection, and in 88 over a home
one. Nothing is held back from a self-hosted deployment. See
[self-hosting](/docs/start/self-hosting/).

## How is this different from Tailscale?

Tailscale is a better mesh network — more years, more platforms, more polish in
that lane. MeshHarbor's difference is that the same agent is also a remote desktop
and an SSH server, so you are not running two agents, two control planes and two
audit trails on every machine. See [MeshHarbor vs Tailscale](/docs/compare/tailscale/).

## How is this different from RustDesk or TeamViewer?

RustDesk is a mature open-source remote desktop, and TeamViewer has two decades
of polish. Neither also gives you a private network: with MeshHarbor the machine you
just connected to is already reachable by address and name, so a port forward or
an SSH session needs no second product. See [MeshHarbor vs
RustDesk](/docs/compare/rustdesk/) and [MeshHarbor vs
TeamViewer](/docs/compare/teamviewer/).

## Does it work behind a corporate firewall?

Usually, yes. Agents need only outbound access and never an inbound port. With
every UDP path blocked the mesh still runs over TLS on port 443, so connectivity
is never all-or-nothing — the connection quality degrades rather than failing.

## Do I need to open ports or forward anything on my router?

No. Both ends connect outbound and meet in the middle. The only inbound port
anywhere is on a machine you deliberately configure to relay other machines'
traffic.

## Why is my session slow?

Almost always because the two ends fell back to a relay. Run `meshharbor peers` or
check the session's connection indicator — if it says **Relay**, that is the
answer, and the most common cause is a VPN client on one end capturing the local
network range. See [cannot connect](/docs/troubleshooting/cannot-connect/).

## Why is the remote screen black, or just wallpaper?

Almost always a capture permission, not a network problem — and operating systems
report no error when one is missing. On macOS, wallpaper-only means the Screen
Recording grant. On Windows, freezing at the lock screen means the agent is not
in system service mode. See [black screen](/docs/troubleshooting/black-screen/).

## Can I reach a machine that nobody is logged into?

On Windows and Linux, yes. Windows needs the system service mode, which can reach
the lock screen and the pre-logon desktop; Linux headless machines use a virtual
display. macOS cannot: screen capture there requires a GUI login session, so a
Mac must be logged in, though it may be locked.

## Does the person at the machine have to approve?

By default, yes — and an absent setting means ask, not allow. You can set a
device to unattended access, which is the right answer for your own servers and
the wrong one for a colleague's laptop. See [consent](/docs/remote-desktop/consent/).

## Can I SSH to a machine without installing an SSH server?

Yes. MeshHarbor serves SSH on a machine that runs no `sshd`, binds no port and needs
no firewall rule, including on Windows. It is off by default behind four
independent gates. See [SSH](/docs/network/ssh/).

## Which browsers work?

Chat, calls, the dashboard and the remote-desktop viewer all work in current
Chromium browsers, Firefox and Safari. For remote desktop we recommend Chrome,
Edge or another Chromium browser: that is where the viewer's low-latency decode
path has had the most testing. Safari and Firefox work too, with less testing so
far.

## Can one machine be in two organizations?

Yes — one agent with several enrollments. Do not install a second copy of the
agent: it would fight the first over the network adapter, the local socket and
the routing state. Note that joining a second organization needs an agent
restart. See [multi-org](/docs/network/multi-org/).

## What happens when I remove a device?

Its credential is revoked immediately, every other machine is told to forget it,
and its mesh address returns to the pool for the next joiner. Re-enrolling the
same machine gives it a **new** address, so anything pinned to the old one needs
updating.

## How do I know the software I downloaded is really yours?

Windows binaries are Authenticode-signed by G ROX LTD; Linux and macOS artifacts
carry GPG signatures against a published key, plus build provenance. The
auto-updater checks the signature **and** the publisher name, and refuses
anything that fails either. See [signed
releases](/docs/security/signed-releases/).

## Is it open source?

Yes. The server is AGPL-3.0 and the agent that runs on your machines is MPL-2.0.
The source is at
[github.com/jk-zhang-meta/MeshHarbor](https://github.com/jk-zhang-meta/MeshHarbor).

## Can it record remote sessions for compliance?

No, and this is deliberate rather than unimplemented. Recording a terminal or a
desktop means shipping whatever an operator typed — passwords, credentials — off
the machine. Session *metadata* is audited in detail; contents are not. If you
need session recording, this is a genuine gap.

## Where do I report a problem?

[github.com/jk-zhang-meta/MeshHarbor/issues](https://github.com/jk-zhang-meta/MeshHarbor/issues).
Include `meshharbor status` output — and for a connectivity problem, from both ends.
Security issues should be reported privately; see
[`SECURITY.md`](https://github.com/jk-zhang-meta/MeshHarbor/blob/master/SECURITY.md).
