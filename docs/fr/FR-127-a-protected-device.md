# FR-127: A protected device — one device-local switch that closes every way in

> **Status:** in progress — claimed 2026-11-23. Tracking issue: none (GitHub Issues are disabled on
> `jk-zhang-meta/MeshHarbor`); this spec and its registry row are the record.

## Goal

The owner of a high-value host (a multi-GPU server with weeks of model weights on it) turns on **one
device-local switch**, and the host refuses every way in that the device itself did not allow:
fleet exec, remote configuration, unattended remote desktop, file browse and transfer, RDP over the
mesh, tunnel exits and SSH forwards with no allowlist, serving as a relay or exit node, cross-org
access, agent sessions and the vault. The switch survives a compromised server or org admin,
because nothing the server sends can turn it off, and it reports what it left open.

Operator, 2026-11-23, on the protection plan for a high-value server: "是为了防止其他机器的可能出现的病毒
感染这台机器，我需要非常完善的机制", then "按照推荐实现吧". The threat is lateral movement INTO the
host from the operator's own other machines (an infected laptop, a lab peer on the same LAN or mesh,
a compromised management plane).

The full design study, with the threat model, host-side controls that need no product change, and 15
product gaps, is the defense plan this FR builds from (kept outside the repo). This FR builds its G1
(the switch) first; the other gaps are listed below and come as later phases or FRs.

## Why one switch

Every plane already has a device-local switch, and they live in one config file. But an ordinary
sign-in turns several of them on for a personal device (`crates/agent-core/src/enrollment.rs:291-323`),
and nothing names the posture as a whole. An owner who wants the host closed has to know about all of
them, and one forgotten key stays open. A switch that only an owner who knows them all can use is
not a mechanism.

## Key design

- **The key:** `protected = true` in the device's config (`crates/agent-core/src/config.rs`),
  device-owned like `remote_config_enabled`: structurally absent from `DesiredConfig`, so remote
  configuration can neither set nor clear it, and it holds whatever the server says.
- **An effective view, not a rewrite.** The daemon saves its config back (key rotation, enrollment
  updates), so forcing the stored values would destroy the owner's own settings the first time it
  did. Instead each gate asks an accessor (`cfg.exec_allowed()`, …) that reads the stored value AND
  `protected`. Turning the switch off restores exactly what the owner had.
- **Every decision point, not every read.** A gate applies at every entry point, or it is a courtesy.
  The refusal sites are listed in the phase table with their `file:line`, and a test drives each.
- **The refusal is attributable.** Each refused request answers or logs "refused: this device is
  protected", so the owner can tell it from a server-side denial.
- **It reports.** The daemon logs the posture at start with the planes still open (SSH, if the
  owner kept it as the admin path, and any explicit `forward_acl` allowlist); `mh config get
  protected` reads the switch. `mh status`, the device report and the console come in P2: adding
  the field to the LocalAPI `NodeStatus` touches four crates, the desktop app among them.

| Plane | Under `protected` |
|---|---|
| Remote configuration | refused (as `remote_config_enabled = false`) |
| Fleet exec | refused |
| Remote desktop | never auto-granted: a person at the device must approve (consent floor) |
| RC file browse, files, clipboard | off |
| RDP over the mesh | off |
| Tunnel exits and SSH `-L`/`-D`/`-J` | only to an explicit `forward_acl` allowlist; an empty list refuses everything |
| Serving as an org relay or exit node, advertising routes | off |
| Cross-org access, agent sessions (hive), vault | off |
| MeshHarbor SSH | as the owner configured it: the admin path, with its own key list |

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P1 | The key, the accessors, every refusal site, the posture at start; tests | `protected = false` (the default) | built, not released |
| P2 | The posture in `mh status`, the device report and the web console (a badge, the open planes) | — | — |
| P3 | Sign-in and `install.sh --protected`, so a server is closed from its first minute (gap G11) | — | — |
| P4 | Device-owned inbound allowlist for the overlay (G2), SSH and exec bound to an origin device (G3) | per-device | — |
| P5 | Operator-signed SSH grants (G4) and node-key signing (G5): the server can relay, not mint | — | — |
| P6 | Alerts on denied inbound (G8), session revocation (G9), a reversible isolate (G10) | — | — |
| Docs | `docs/protected-device.md` (mermaid, tables, anchors) and a `docs/README.md` index row | — | — |

## Acceptance criteria

- [ ] **AC1.** With `protected = true`, each plane in the table refuses on a real device of each OS
  family the fleet has (Linux root, Linux user-mode, Windows, macOS), shown failing (allowed) with
  the switch off first.
- [ ] **AC2.** Remote configuration cannot clear `protected` or reopen a plane: a pushed
  `exec_enabled = true` leaves exec refused.
- [ ] **AC3.** Turning the switch off restores the owner's previous settings exactly (the stored
  config is unchanged by protection).
- [ ] **AC4.** The device names its posture and every plane left open: in its log at start (P1)
  and in `mh status` and the console (P2).
- [ ] **AC5.** Docs: `docs/protected-device.md` and a row in `docs/README.md`'s index, before close.

## Out of scope (other FRs or the host itself)

Host controls that need no product change (loopback-only model APIs, a proxy in front of vLLM,
hardware-backed SSH keys, append-only backups, firewall with an automatic revert) are the owner's,
listed in the defense plan's checklist. Container escape and GPU firmware are outside the daemon.

## Field log

| When (UTC) | What | Result |
|---|---|---|
