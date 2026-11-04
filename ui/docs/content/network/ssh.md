---
title: SSH without sshd
description: Get a real shell on any enrolled machine by its mesh address — with no sshd installed, no port bound and no firewall rule, on Linux, macOS and Windows.
tags: [network, ssh, security, access-control, windows, linux, macos]
order: 7
---

MeshHarbor can serve SSH on a machine that **runs no `sshd`, binds no port and
needs no firewall rule** — including Windows, where an SSH server is usually a
separate project.

```bash
ssh dev-box
```

## Why there is no listening port

The agent intercepts SSH traffic **below the operating system's socket layer**:
packets addressed to the machine's own mesh address on the SSH port are diverted
into the agent before the OS ever sees them.

That is not cleverness for its own sake — it is what makes the feature possible
at all:

:::badges
- **Binding a port often fails** icon:warning — on a machine that already runs `sshd`, the port is taken for every local address.
- **Nothing for security software to kill** icon:shield — there is no `sshd` process for an endpoint agent to terminate.
- **Unreachable off-mesh by construction** icon:network — not "closed by a firewall rule" but "there is nothing listening at all".
:::

It also means it works on locked-down corporate machines where installing an SSH
server is not permitted, and on Windows, which it serves the same way it serves
everything else.

## What works

:::cards
- **Interactive shells** icon:terminal — A real terminal, with resize handling, on Linux, macOS and Windows.
- **Commands** icon:check — `ssh dev-box uptime` and friends.
- **File transfer** icon:copy — `scp` and `sftp`.
- **Port forwarding** icon:network — `-L` local forwards, `-J` jump hosts and `-D` dynamic SOCKS.
:::

:::warning `-R` remote forwarding is deliberately not implemented
It would make the machine bind a listening socket — the exact thing this design
exists to avoid — and it is redundant here, because the client is itself a mesh
node and can be reached directly.
:::

## Turning it on

SSH is **off by default and stays off** until several independent things are
true. Each is owned by a different party, and any one of them refuses:

:::steps
1. **The organization** enables remote SSH. It is a separate switch from remote command execution.
2. **The user** has the SSH permission. Also separate — and not included in the default administrator role.
3. **The device** has an SSH policy allowing it.
4. **The machine itself** has SSH enabled in its own configuration, with an authorised key list. Enabling SSH without listing a key grants nobody anything.
:::

:::danger The machine's own setting is the one that survives a compromised server
Gate 4 exists precisely because the server cannot write it. Every other gate is
a policy the control plane enforces; the last one is a decision the machine
holds. That is what makes the whole chain worth having.
:::

## Which account a session runs as

A session runs as **what was actually asked for, never more**. The device
decides which accounts are permitted, and an unset value means *authenticate,
then run nothing* — rather than quietly handing over a root shell.

An unparseable setting is a refusal, not a fallback.

| Account mode | Linux and macOS | Windows |
|---|---|---|
| `daemon` | root | the agent's own account: SYSTEM on a service install, the signed-in user on an attended one |
| `named` | that local account | refused: becoming another user needs their password |
| `console_user` | the person signed in at the machine's own screen | the user signed in at the console |

`console_user` is refused while nobody is signed in at the screen, and never
means root. On Linux "the screen" is the machine's own seat, so someone in a
remote desktop session does not count; on a Mac it is whoever is logged in to
the desktop. The session gets that person's account, not their desktop
session, so a program that needs the desktop (a window, a notification) does
not reach their screen.

A person's session, `named` or `console_user`, starts in their home folder (on
Windows, their profile), as an ordinary SSH server starts it. That holds for the
shell, a command and file transfers, so `scp file node:` lands in the home. If
the home is missing or cannot be entered, the session starts in `/` instead of
failing.

## Port forwarding is default-deny

:::warning An empty forward allow-list means *nowhere*, not *anywhere*
This is the opposite of the tunnel path, and the reason is worth understanding: a
tunnel flow was already authorised by the server before it reached the machine,
so an empty local list sensibly means "no extra restriction". An SSH
`direct-tcpip` channel has **no server in the path at all** — so an empty list
must mean nothing is permitted, or every SSH session would be a silent open pivot
into whatever that machine can reach.
:::

Refusals tell the client whether it was **policy** or an **unreachable
destination**, so you can act on the difference. The reason text stays in the
machine's log, because it names internal topology.

:::tip `-J` needs the *jump* host to allow the final target
A jump-host hop is authorised by the machine doing the jumping, not by your
client. If `-J` is refused, the allow-list you need to change is on the jump
host.
:::

## Consent

Depending on the device's policy, a session may prompt the person at the machine
before it starts. The prompt fires when the session is **redeemed**, not when it
is authorised, so a refusal can explain itself on your terminal instead of
appearing as an unexplained rejected connection — and you are told a wait is
happening rather than left looking at a hang.

## What gets recorded

Two separate records, deliberately not merged:

| Record | Written by | Is |
|---|---|---|
| **The decision** | The server | Authoritative — who asked, for what, and whether it was granted or refused, with the reason |
| **The activity** | The machine | A *claim* by the host: sessions opened and closed, commands run, forwards attempted |

:::warning An empty activity log is not evidence of inactivity
Activity reporting is a machine-side setting that defaults to off, so a machine
that does not report looks exactly like an idle one. The server's own decision
log is what survives a machine that lies.
:::

:::danger Session contents are never recorded
No keystroke stream, no command output. Recording a terminal would mean shipping
whatever an operator typed — passwords into `sudo`, credentials into a database
client — off the machine, which is the opposite of what this product promises.
:::
