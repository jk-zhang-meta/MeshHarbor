---
title: CLI reference
description: Every meshharbor command — status, peers, why, netcheck, forwards, routes, exec, ssh and diagnostics — with the flags that actually exist.
tags: [reference, cli, commands, tunnels, diagnostics]
order: 1
---

`meshharbor` is the command-line tool. On a machine that also runs the agent it is
a thin shim onto the agent's own command surface, so the two can never disagree
about their version.

:::warning `--agent` takes the hex device id
`--agent` on `forward`, `socks5` and `route add` takes the **hex device id** from
the dashboard; a name is not resolved there, and passing one fails in a way that
looks like the device is missing rather than like a bad argument. The target of
`exec`, `ssh` and `ping` is different: it takes a device name, a dashboard
display name or the hex id — see Remote access below.
:::

## Status and inspection

| Command | Does |
|---|---|
| `meshharbor status` | This machine: id, version, mode, mesh address, server connection — **and** the mesh state per organization |
| `meshharbor peers` | Every peer the local agent sees, with its live connection type |
| `meshharbor peers --display-name` | The same table, with the dashboard display name in NAME where one is set (`--json` gains a `display_name` per peer) |
| `meshharbor peers <name>…` | Only those peers — each a device name or a display name, in the order given |
| `meshharbor why <peer>` | Why **one** peer rides the path it does: the ladder, each tier's eligibility, and any hold-down overriding the ranking |
| `meshharbor netcheck` | This machine's measured network capability: reachability, relay verdict, floor health, NAT class |
| `meshharbor flows` | Flows the local agent is currently running |
| `meshharbor logs --tail <n>` | Tail the agent's log, resolved **by** the agent — the path differs per process and platform |
| `meshharbor ping <peer>` | Reachability over the mesh — by device name, display name or overlay address |

:::tip `why` is the command to reach for on a relay question
`peers` tells you a pair is relayed. `why` tells you which tier was eligible,
what it scored, and whether something is holding the decision down — which is
the difference between knowing and guessing.
:::

:::warning `meshharbor logs --grep` reads a bounded tail
It searches a slice of the end of the log, not all of it. **A negative result is
not proof of absence.**
:::

## Tunnels

```bash
meshharbor forward --agent <id> --local 5432 --remote localhost:5432
meshharbor forward --agent <id> --local 5432 --remote db.internal:5432 --daemon
meshharbor socks5  --agent <id> --local 1080
meshharbor socks5  --local 1080                  # mesh mode: omit --agent
meshharbor kill <flow-id>
```

| Flag | Means |
|---|---|
| `--agent` | Hex device id of the far end. On `socks5`, **omitting** it selects mesh mode |
| `--local` | Local port to listen on, bound to loopback |
| `--remote` | `host:port` the far end dials |
| `--daemon` | Hand the flow to the local agent so it outlives this command |

Both commands stay in the foreground without `--daemon`; `Ctrl-C` tears down.

## Declared routes

Forwards the agent re-establishes on every start:

```bash
meshharbor route add --agent <id> --local 5432 --remote localhost:5432
meshharbor route ls
meshharbor route enable <id>
meshharbor route disable <id>
meshharbor route rm <id>
```

## Remote access

```bash
meshharbor exec <device> -- <command>     # <device>: device name, display name or hex id
meshharbor ssh <device>
meshharbor ping <device>
meshharbor proxy <host> <port>            # for OpenSSH ProxyCommand
```

:::tip How a device selector is read
A hex id or an address is used as is. A device **name** — the one the machine
reported, or the admin-set name — is resolved by the server, as it always was.
A dashboard **display name** is resolved by the CLI from your org's device list,
only when no device name matches it (exactly first, then ignoring case), and
when two devices share one the command refuses and lists both rather than
guessing. `meshharbor proxy` resolves device names and MagicDNS names only.
:::

:::danger On Windows, quote-containing arguments to `exec` can be lost
An argument with spaces can arrive at the far end empty. The tell is a blank
line or a zero-byte file rather than an error. Prefer `meshharbor ssh` when the
command has arguments that need quoting.
:::

`meshharbor proxy` is for OpenSSH's `ProxyCommand` — transport and name resolution
only. It cannot supply an identity or a host key, so it uses keys **you**
manage. For a session where the account is resolved by policy and the host key
is verified for you, use `meshharbor ssh`.

## Diagnostics

```bash
meshharbor diag host                  # evidence bundle from one device
meshharbor diag pair <other-agent-id> # both ends, side by side
meshharbor diagnose --agent <id>      # probe MTU, candidates and relay status from HERE
```

:::tip `diag` and `diagnose` are different tools
`diagnose` probes **from this machine**. `diag` runs a canned, OS-appropriate
evidence set **on the target devices** — adapters, routes, firewall posture,
carrier state, recent warnings — which is what a "why is this pair relayed?"
question actually needs.
:::

## Configuration and identity

```bash
meshharbor config ls
meshharbor config set <key> <value>
meshharbor config clear <key>
meshharbor rename <new-name>
meshharbor enroll --server <url> --token <token> --name <name>
meshharbor self-update
```

:::warning `self-update` refuses on a machine that runs the agent
There the installer owns the whole node stack and `meshharbor` is a shim with
nothing of its own to update. It is the real updater only on tunnel-only
machines.
:::

## Organizations

```bash
meshharbor org ls
meshharbor org overlay <org> tun
meshharbor org set-primary <org>
meshharbor org rm <org>
```

## Agent sessions you run in a terminal

```bash
meshharbor hive adopt      # mirror the Claude Code sessions you run in a terminal into MeshHarbor
meshharbor hive unadopt    # take the hooks out again
```

`adopt` adds three hooks to **your own** user-level Claude Code settings
(`~/.claude/settings.json`, or `$CLAUDE_CONFIG_DIR/settings.json`) and leaves
every other setting and hook in that file as it was; `unadopt` takes out
exactly those three. On Windows each hook runs `meshharbor.exe` from the PATH the
installer set. Each session you then run in a terminal is mirrored by
this machine and listed for you alone in MeshHarbor, read-only: nobody prompts it
from there, and you may name readers. Nothing happens until this machine's
owner turns on `hive_adopt` and maps your account in `hive_accounts`
([configuration](/docs/reference/configuration/)). **Stop mirroring** in
MeshHarbor stops watching that terminal run; the terminal goes on. A
`claude --resume` of it later is mirrored afresh, as a new session.

:::tip What leaves the machine
The server keeps that a session exists, its folder and its turns' sizes —
never what you typed or what came back. The transcript stays on this machine
and reaches your browser over a direct, encrypted peer.
:::

## Getting help

Every command takes `--help`, and that is authoritative for the version you have
installed:

```bash
meshharbor --help
meshharbor forward --help
```
