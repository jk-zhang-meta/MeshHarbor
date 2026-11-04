---
title: Configuration reference
description: The agent's config.toml — where it lives per platform, the settings worth knowing, and which ones the server can and cannot change.
tags: [reference, configuration, agent, security, admin]
order: 2
---

The agent reads one `config.toml` per machine.

## Where it lives

| Platform | Path |
|---|---|
| Windows, per user | `%APPDATA%\meshharbor\config.toml` |
| Windows, machine-wide | `%PROGRAMDATA%\meshharbor\config.toml` |
| Linux, system service | `/etc/meshharbor/config.toml` |
| Linux, per user | `~/.config/meshharbor/config.toml` |
| macOS, root half | `/etc/meshharbor/config.toml` |

:::danger This file is a credential store
It holds the agent token and, if SSH is enabled, the SSH host private key. It is
written with restrictive permissions, and the machine-global directory on
Windows is explicitly hardened at install time because its default permissions
are readable by all local users.

Never copy it between machines: identity is meant to be per-machine, and a
shared credential destroys the audit trail.
:::

## Reading and writing it

Prefer the CLI over editing by hand — it writes atomically and keeps a previous
copy:

```bash
meshharbor config ls
meshharbor config set <key> <value>
meshharbor config clear <key>
```

:::warning A local edit takes effect immediately where the setting allows it
Settings that can be applied live are applied live when *you* change them
locally, exactly as they are when the server pushes them. Making a server push
live while the machine owner's own edit waited for a restart would invert the
property these gates exist for.
:::

## Identity

| Key | Meaning |
|---|---|
| `server_url` | Which server this machine belongs to |
| `agent_token` | The credential. Written by enrollment; never edit |
| `name` | Display name in the dashboard |

## Network

| Key | Meaning |
|---|---|
| `overlay_mode` | Whether and how this machine joins the mesh |
| `overlay_exit_node` | The exit node to route all traffic through, by name |
| `overlay_exit_node_enabled` | Offer this machine as an exit node (an admin must still approve) |
| `relay_server_enabled` | Let this machine relay other machines' encrypted traffic |
| `[[tunnel_routes]]` | Declared forwards the agent re-establishes on every start |

## Remote access — all default-deny

| Key | Default | Meaning |
|---|---|---|
| `exec_enabled` | off | Allow remote command execution at all |
| `ssh_enabled` | off | Run the SSH server |
| `ssh_port` | `2222` | Not 22, so an existing `sshd` keeps serving during a migration |
| `ssh_authorized_keys` | empty | **Empty means nobody.** Enabling SSH without listing a key grants nothing |
| `ssh_account_mode` | unset | Which account a key-list session runs as. Unset means authenticate, then run nothing |
| `ssh_host_key` | minted | Generated on first SSH-enabled start |
| `forward_acl` | empty | SSH port-forward destinations. **Empty means nowhere** |
| `ssh_activity_log` | off | Whether this machine reports what its SSH sessions did |
| `ssh_exec_streaming` | on | Stream a one-shot command's output as it is produced, with no 1 MiB ceiling and no time limit; the command ends when the SSH channel does. Off restores the buffered path. Restart required |
| `hive_enabled` | off | Run AI agent sessions here when an org member starts one (Linux, macOS and Windows agents). A session survives a restart of the agent: it resumes with its history once the agent is back online, if this machine's settings still allow it then. On Windows a session runs as the user signed in at the console, at normal (Medium) integrity, never elevated; with nobody signed in, a start is refused. A remote-desktop connection to the machine does not interrupt its sessions |
| `hive_accounts` | empty | Which local account each member's sessions run as, `{"<user id or email>": "<account>"}`. **Empty means nobody**; never root. On Windows it must name the user signed in at the console, as `name`, `DOMAIN\name` or `.\name`: a session runs only as that user. A session never holds the account's administrator groups (`sudo`, `wheel`, `admin`, `docker`, …), and on Linux it cannot gain a privilege at all: no `sudo`, whatever sudoers says. On macOS `sudo` reads the account's groups from the directory, so a start as an account whose `sudo` needs no password, by any rule, is refused unless `hive_allow_passwordless_sudo` is on |
| `hive_roots` | empty | Folders sessions may run in, checked on the resolved path. **Empty means nowhere** |
| `hive_max_sessions` | `4` | Sessions this machine runs at once |
| `hive_api_key_helper` | unset | A command **the daemon** runs (as SYSTEM/root; on Windows through `cmd.exe /c`) to print the model credential: an API key, or a Claude subscription's token from `claude setup-token`, which is sent as one (a bearer token; it spends the subscription owner's own usage limits, for every session on this machine). Sessions never see it: each gets a token for this machine's loopback model sidecar, good only for that session's model calls while it runs here — not for anything else the key opens, such as files or batches. Unset means sessions have no model access |
| `hive_api_workspace_id` | unset | For a model key that is not scoped to a workspace: the workspace its calls are made in. The sidecar sends it as `anthropic-workspace-id` with every call, alongside the key; sessions never set it. Leave unset for a workspace-scoped key |
| `hive_core_memory` | off | Show the organization's core memory — the facts its people keep in MeshHarbor — to the agent sessions on this machine, as the session's `CLAUDE.md` and auto-memory. Claude Code reads `CLAUDE.md` as the user's own instructions, so this is the one place text from the server reaches a session; it is yours to turn on. A session keeps the memory it started with, and a resume keeps the session's own copy |
| `hive_adopt` | off | Let the people who use this machine adopt the Claude Code sessions they run in a terminal (`meshharbor hive adopt`; Linux, macOS and Windows): mirrored into this machine's store and shown to their owner alone, read-only — nobody drives them from MeshHarbor. Each person still opts in, and their account must map in `hive_accounts` to exactly one member; a shared account is refused. Restart required |
| `hive_allow_passwordless_sudo` | off | macOS only: let agent sessions run as an account whose `sudo` needs no password. That gives the agent root, whatever groups the session drops, because macOS's `sudo` reads the account's groups from the directory. Off, such a start is refused (`passwordless_sudo`); a Mac whose `sudo` asks for a password, as macOS's does by default, is unaffected. No effect on Linux, where a session cannot `sudo` at all. Never settable by the server. Restart required |
| `hive_replica` | off | Hold copies of the agent sessions you run on your other machines, so a session can move here when its machine is gone. A copy is everything the agent saw, kept in plain text on this machine. Replication is still being built: until it ships, this only makes the machine keep a session store. Never settable by the server. Restart required |
| `hive_archive` | off | Offer this machine as your organization's archive replica: once an administrator designates it, it holds every agent session your organization's rules allow, for their retention. Needs `hive_replica` on. Never settable by the server. Restart required |
| `hive_store_quota_mib` | unset | The most this machine keeps of the agent sessions it holds as a replica, in MiB (1–4194304). Unset: no bound but the disk's. Never settable by the server. Restart required |
| `hive_update_wait_secs` | `1800` | How long an update waits for running agent turns before it restarts the daemon (0–7200 seconds; `0` never waits). The sessions resume after the restart, but a turn still running is cut. It holds a server-pushed update too. While it waits, the log says so once a minute; once it goes ahead, new prompts are held until the restart. On macOS, where a separate root helper installs updates, the helper asks the agent to wait the same way |

:::danger These are the gates the server cannot write
Every one of the settings above is device-owned. That is the property that makes
them meaningful — a server-side gate falls if the control plane is compromised;
a machine-held one does not.
:::

:::warning `ssh_port` defaults to 2222 on purpose
Binding 22 fails on a machine that already runs `sshd`, because that server
covers every local address. The agent warns when its port shadows an existing
one.
:::

## Remote desktop

| Key | Default | Meaning |
|---|---|---|
| `keep_busy_enabled` | **on** | Let a remote-desktop controller with input turn on *keep busy* here: the pointer moves in a pattern so the screensaver, the idle lock and "Away" never come, and any real input — yours or a controller's — pauses it. Off hides it from the viewer, refuses new enables and stops one already running. Your organization can also deny it. Never settable by the server. Applied live |

:::note The one remote-access feature that is on by default
It only moves the pointer, never clicks or types, and the person at the
machine always wins: touch the mouse or the keyboard and it stops until you have
been idle again. Stop it from the tray, or with `meshharbor keep-busy off`.
:::

## Media

| Key | Meaning |
|---|---|
| `encoder_preference` | `auto`, `hardware` or `software` |

Resolution order is **command-line flag → environment variable → config file →
default**.

## Remote configuration

| Key | Default | Meaning |
|---|---|---|
| `remote_config_enabled` | off | Allow the dashboard to change this machine's settings |
| `auto_update` | on | Let the agent update itself |

:::danger `remote_config_enabled` is structurally absent from anything the server can push
A machine that sets it has knowingly delegated its last gate to its control
plane. A machine that has not, has not — and there is no server-side action that
changes that. The value can only be set on the machine.
:::

:::warning An isolated `--config` does not isolate the updater
Running a second agent against a separate config file does **not** give it a
separate updater. It will still update the machine's installed binaries
system-wide. If you are running a probe or a test instance, set
`auto_update = false` on it.
:::

## Settings applied live versus on restart

| Applied | Which |
|---|---|
| **Live** | `exec_enabled`, `keep_busy_enabled`, most network settings |
| **On restart** | The SSH settings — the SSH server splices into the packet path when the mesh is built |

A machine reporting `needs_restart` after a configuration push is telling the
truth rather than failing.

:::warning The agent will not restart itself
Deliberately: nothing can reliably tell whether it is supervised, and exiting an
unsupervised agent would take that machine permanently offline. Restart it
yourself, or on the next reboot.
:::

## Server configuration

Self-hosted server settings are environment variables prefixed `MESHHARBOR__`,
covered in [self-hosting](/docs/start/self-hosting/).
