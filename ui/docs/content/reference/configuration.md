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
mh config ls
mh config set <key> <value>
mh config clear <key>
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
been idle again. Stop it from the tray, or with `mh keep-busy off`.
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
