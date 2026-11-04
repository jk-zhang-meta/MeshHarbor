# FR-43: One macOS device row — a supervising daemon and an unenrolled GUI worker

**Status:** P0 + P1 + **P2 complete and field-verified** (0.4.33 → 0.4.43) — the daemon's row streams real pixels; P2c/P3 next. Tracking issue: `FR-43`.

⚠️ Anchors RE-VERIFIED against master `9700e9ff` on 2026-09-06, when this record was
landed 27 releases after the field run. `remote_control`'s hub moved to
`crates/modules/fleet/src/hub.rs` in the interim and every citation to it was stale —
which is exactly why the convention asks for a master sha rather than a bare line number.

## Goal

A Mac appears in Devices **once**, like every other platform, while keeping both things
it can do today: remote desktop from the GUI session, and overlay mesh + SSH from boot.
One enrollment, one control WS, one row to `exec` and `ssh` against.

## Why there are two of them today, and what is actually forced

macOS is the only platform that needs **two processes**, and that half is not
negotiable:

| Plane | Needs | Where it must run |
|---|---|---|
| capture / input / clipboard | a WindowServer connection | the console user's GUI session |
| `utun` + route table + SSH | root | session 0 |

`docs/installation.md:104-113` states it; `agents/meshharbord/packaging/macos/fans.itachi.meshharbor.agent.plist`
and `fans.itachi.meshharbor.daemon.plist` are the two units, and both invoke the *same* binary with
the same `run` subcommand — the split is context, not code.

**Windows does not need two because a SYSTEM process can reach the interactive desktop.**
`agents/meshharbord/src/win_service/desktop.rs:1-16` documents the mechanism (a thread
attaches to `winsta0\Default` / `winsta0\Winlogon` and captures/injects there), and
`win_service/supervisor.rs:266` (`spawn_in_session`) + `:746` (`decide_spawn`) is the shape: the SCM
service supervises, the agent proper runs in a session. macOS has **no `SetThreadDesktop`
equivalent** — a session-0 daemon cannot borrow the console user's WindowServer, at all.
That is the whole asymmetry.

**What is NOT forced is two enrollments.** That comes from us: the hub keys a device's
control WS on `agent_id` and a second connection displaces the first
(`crates/modules/fleet/src/hub.rs:94`), so we gave each half its own identity and the
Mac became two rows. Cost, paid daily: every `meshharbor exec` / `meshharbor ssh` must target
the *right* row (the GUI row cannot reach root, the root row cannot see the screen), the
install needs two tokens, and Devices shows one machine twice.

## Key design — port our own Windows supervisor to launchd (P1; see the P2 correction below)

The root daemon becomes the **single enrolled identity** (control WS, overlay, SSH, from
boot); the GUI-session process becomes an **unenrolled worker** it spawns and drives.

- **Spawn**: root → `launchctl asuser <console-uid>` (or a daemon-managed LaunchAgent),
  the launchd analogue of `spawn_in_session`. Console-user changes (login, logout, fast
  user switch) drive respawn, mirroring `decide_spawn`'s session-change handling.
- **Transport**: the LocalAPI unix socket, which already solves exactly this addressing
  problem — `crates/localapi/src/lib.rs:1966-1875` documents `/var/run/meshharbor` as the
  root daemon's well-known socket precisely because "a per-user path cannot serve a root
  daemon … that is the trap the macOS LaunchDaemon split walks into".
- **Division**: signalling + consent + policy in the daemon; the rc session's WebRTC
  peer, capture, encode, input, clipboard and file transfer in the worker (media stays
  local to the session that can produce it — no pixels cross the socket).
- **TCC**: the worker is the same bundle at the same path, so Screen Recording and
  Accessibility grants carry. This is only safe *now*: before FR-5's stable signing
  identity, any change to how the capture process launches risked re-prompting on every
  update. `codesign -d -r-` equality is the pre-flight check (FR-5's method).

## Phases

| P | Scope | Kill switch |
|---|---|---|
| P0 | Spike: daemon spawns a GUI worker via `launchctl asuser`, worker answers a LocalAPI caps probe from the daemon. Measures the respawn latency and the TCC verdict. | n/a (spike, no ship) |
| P1 | Daemon-as-supervisor: spawn + babysit + session-change respawn. Worker still enrolled — nothing changes for the server yet. | `macos_supervise_gui_worker` (default **off** ⇒ today's two independent halves) |
| P2 | Session delegation: the daemon's WS accepts an rc session and drives the worker over LocalAPI. | per-session fallback — delegation failure re-serves from the worker's own enrollment |
| P2c | The daemon's row advertises the WORKER's `permissions`, so the dashboard stops calling a working capture target "not a capture target". | caps are only ever sent when they CHANGE; absent field = today's behaviour |
| P2d | The installer stops reverting P2 on every update: with the daemon supervising, the `.pkg` no longer re-bootstraps the per-user LaunchAgent. | the guard needs BOTH the daemon opt-in and `macos_supervise_gui_worker = true`; either absent = today's behaviour byte-for-byte |
| P3 | Collapse the enrollment: installer mints ONE token; existing two-row Macs migrate. | `--daemon-token` keeps working (two-row install stays reachable for a release) |

## P2 design — session delegation over LocalAPI

Anchors below verified against master `3980e79d`.

### ⚠️ First, a correction to "Key design" above: P2 has no Windows precedent

"Port our own Windows supervisor to launchd" is true of **P1 and only P1**. The Windows
SCM service is a *pure launcher*: `win_service/mod.rs:396` hands off to
`supervisor::run(worker_exe, vec!["run"], …)` and does nothing else, so the spawned worker
is the entire agent — control WS, overlay, capture, input, all in one process. Windows
never had to split the planes, because a SYSTEM process can attach to the interactive
desktop (`win_service/desktop.rs`). **There is no delegation protocol to port.** P2 is new
work, and the design below should be read as such rather than as a translation.

### Why not the Windows shape (worker enrolled, daemon only supervising)

Because it deletes the reason the macOS daemon half exists. With nobody logged in there
would be no agent at all: no overlay, no `meshharbor ssh`, no `meshharbor exec`, no presence —
exactly the "reachable before anyone logs in" property `win_service/mod.rs`'s own module
docs list as the point of service mode. So the **daemon must hold the enrollment**, and
the session has to reach the worker some other way.

### Why not "let the worker open its own WS for the session"

Tempting, and it would remove the IPC entirely. It cannot work as-is: `Hub::register_agent`
(`crates/modules/fleet/src/hub.rs:376`) is keyed on `agent_id`, and a second connection
**displaces** the first — the displaced socket is cancelled within milliseconds by design
(`hub.rs:94-99`). A worker dialling in as the same device would knock the daemon's control
WS off the air, which is precisely the login/displace/relaunch loop P1's stand-down exists
to prevent. Making it work would mean teaching the server about session-scoped secondary
connections: a server change, a new authenticated surface, and a new way for a compromised
device to hold two sockets. Not worth it to avoid a unix socket we already own.

### What actually has to cross the boundary

Of the 28 `ServerMsg` and 28 `ClientMsg` variants the agent handles today, the rc session
needs **nine**, and no media among them:

| direction | messages |
|---|---|
| daemon → worker | `SessionCreated`, `SdpOffer`, `SdpAnswer`, `Ice`, `Terminate` |
| worker → daemon | `SdpAnswer`, `Ice`, `SessionStats`, `Terminate` |

Everything else stays where it already is: `RpcExec*`, `Ssh*`, `Tunnel*`, `Config*`,
`Derp*`, `KeyRotate`, `JoinOrg` and the whole overlay are daemon-side concerns and do not
move. Input, clipboard and file transfer ride the session's **data channels**, so once the
worker owns the peer they never touch the socket either. Pixels never cross it. This is the
property that makes the whole phase affordable: the IPC carries a few hundred bytes at
session setup and then nothing.

### The transport problem, stated honestly

LocalAPI is **strictly request→response**: `serve_connection` reads newline-delimited JSON,
answers each line, and loops to EOF (`crates/localapi/src/lib.rs:1718`); `TailLog`'s
own doc calls itself "poll-based follow (no streaming)" (`lib.rs:1051`). There is no server
push, and delegation needs it in both directions — trickle ICE arrives whenever the network
decides, not when someone asks.

Three options, and the trade is latency versus a protocol exception:

1. **Long-poll** (`RcPoll` blocks until a frame is queued, `RcPush` for the reverse). Fits
   the existing protocol with zero changes. Costs a round-trip of latency on every ICE
   candidate — i.e. on the session-setup critical path — and still holds a connection open
   permanently, so it buys nothing operationally.
2. **One streaming verb** — `RcAttach`. The worker connects and sends it; from that point
   the daemon treats *that connection* as a bidirectional frame channel until EOF. A
   documented, single-verb exception to the request/response rule, confined to one match
   arm and invisible to every other caller.
3. **A second LocalAPI server in the worker**, so daemon→worker push is an ordinary
   request. No protocol change, but two dispatch surfaces to secure instead of one, a
   second socket path to agree on, and a startup ordering problem (the daemon cannot push
   before the worker's listener exists).

**Recommendation: (2).** The exception is real and should be written down rather than
disguised as polling. It keeps one socket, one ACL, one dispatch surface, and it is the
only option whose latency does not sit on the path a human perceives as "how long until my
screen appears".

⚠️ `RcAttach` must be **daemon-only**, not something any local process can call: it would
otherwise let any user-session process on the box volunteer to serve remote-control
sessions. The socket's own ACL is the trust boundary today
(`lib.rs:1818-1828` — `/var/run/meshharbor`, 0600), which is *not* sufficient on its own here,
because the worker is an ordinary user process and so is an attacker's. The attach must
carry the one-shot secret the daemon passed to the worker in its spawn environment, and the
daemon must accept exactly one attached worker at a time.

### Consent

Stays in the daemon, and this is not a compromise — FR-27 already built the mechanism.
`PromptSurface` (`agents/meshharbord/src/consent.rs:184`) is a chain, and its **companion**
rung is precisely "a per-user process the daemon starts on demand"
(`companion::ensure_running()`). A session-0 daemon has no native surface and correctly
falls through to it. So the daemon keeps the policy decision (`strictest_of`, the local
floor) and the prompt appears in the user's session, with no new mechanism.

### Kill switch and fallback

Per the phase table: delegation failure **re-serves from the worker's own enrollment**.
That is only meaningful while P2 and P3 are separate — during P2 the worker is still
enrolled, so a failed `RcAttach` means the daemon declines the session and the worker's own
WS serves it exactly as today. ⚠️ This makes P2 genuinely reversible and P3 genuinely not:
once the second enrollment is gone, the fallback is gone with it. P3 must therefore not
ship until P2 has field evidence, not merely CI.

### P2b-2 design — the worker serves a delegated session

Measured against master `4fa59b9c`, and the measurements are what make it small.

### The seam is the SENDER, not the message

The instinct is to route each reply as it is produced. That is not needed, and
the numbers say why:

| in the five rc arms | count |
|---|---|
| direct `send_msg(ws, …)` | **3**, all in the `SdpOffer` arm |
| `outbound_tx` uses | **1** — `AgentPeer::new(…, outbound_tx.clone(), …)` |

Everything an rc session later emits — ICE, `SessionStats`, its own
`Terminate` — leaves through the sender the **peer was constructed with**. So a
delegated session needs one decision, taken once, at peer construction: hand it
a sender whose drain wraps each `ClientMsg` in a `DelegateFrame::FromWorker`
instead of the worker's own WS queue. No per-message routing, and nothing
downstream needs to know it is delegated.

The three direct sends are the only remainder, and they take a small
`ReplySink` (`Ws(&mut …)` | `Delegate(&…)`) so the daemon path stays
byte-for-byte what it is today.

### Where the worker runs it

In the loop it already has. The worker keeps its own enrollment and WS through
P2 (that is the fallback), so `connect_once` simply gains the delegation
channel as another `select!` source; delegated messages go through the SAME
`handle_server_msg` with the SAME session state, differing only in the sender
their peer was built with. Session ids come from the daemon's row and cannot
collide with the worker's own.

### It is field-falsifiable, which P2b-1 was not

`AgentCaps.permissions` — including `no-gui-session` — is **reporting only**;
nothing server-side gates session creation on it (`models.rs:112-138` is
explicit that readers should treat it as "not a capture target"). So a
controller can open a session against the DAEMON's row today, and the test is
binary: pixels appear, or they do not.

### Order of work

1. `ReplySink` + the three `SdpOffer` sends (pure refactor, no behaviour
   change on the daemon path).
2. The delegated sender at `AgentPeer::new`.
3. The worker's `select!` arm.

⚠️ Step 1 touches the shared session-setup path, so it breaks remote desktop on
**every** platform if it is wrong — not just macOS. The integration lane
(`agent_e2e_tests` drives a full `rc:*` round-trip in-process) is the check that
actually covers it, and it does NOT run on a PR unless `crates/tests/**` is
touched: dispatch it on the branch before merging.

## Open questions for implementation

- **Session ownership on worker death.** If the worker dies mid-session the daemon holds a
  live server-side session with nothing behind it. It must `Terminate` with a reason the
  controller can act on, rather than let the controller watch a frozen screen — the same
  argument that made `rc:consent.reason` worth splitting in FR-27.
- **Does `SessionCreated` carry everything the worker needs** (permissions, TURN creds,
  relay region) or does the worker need daemon state as well? If the latter, the attach
  handshake should carry it once rather than per-session.
- **Ordering.** ICE candidates may arrive before the worker has attached. The daemon needs
  a small per-session queue, or an explicit "not ready" refusal — silently dropping them
  would produce a session that half-works, which is worse than one that fails.

## P2c design — the daemon's row stops calling itself "not a capture target"

Measured against master `9700e9ff` (2026-09-06).

P2b made the daemon's row able to stream real pixels. It still advertises
`permissions: ["no-gui-session"]`, so the dashboard renders it as *not a capture
target* and the operator has to know the trick to use it. Until that is fixed
the feature works and looks broken, which is close to not working.

### The constraint that shapes everything: caps are announced ONCE

The server takes caps from `rc:agent.hello` and nowhere else
(`crates/modules/fleet/src/socket.rs:60`). `AgentHeartbeat` carries `rss_mb`,
`cpu_pct`, `active_sessions` and `sys` — **no caps**
(`crates/remote_control/src/signaling.rs:623`). There is no post-hello refresh
path at all.

That matters because the worker attaches on its own schedule: the supervisor
spawns it at daemon start and it attaches ~260 ms later, but it also attaches
after a console-user change, after a hand-back, and not at all when nobody is
logged in. Whatever P2c does must cope with caps that become true *after* the
WS is already up.

### Rejected: wait for a worker before saying hello

The obvious fix — delay the hello until a worker has attached, so the caps are
right first time — is **wrong, and expensively so**. It couples the daemon's
control WS to GUI-worker readiness, which destroys the one property the daemon
half exists for: reachable *before anyone logs in*. A headless reboot would
never connect at all, and `meshharbor ssh` / `exec` / the mesh would wait on a
login that may never come. The daemon must say hello immediately and correct
itself later.

### Chosen: an optional `caps` on the heartbeat, sent only when it CHANGES

- **Additive on the wire.** `AgentHeartbeat.caps: Option<AgentCaps>` with
  `skip_serializing_if`, so an older server ignores it and an older agent simply
  never sends it. No version gate, no capability verb.
- **Sent on change, not every beat.** Caps are ~200 bytes and the heartbeat is
  frequent; in steady state this costs nothing. The daemon keeps the last
  announced value and sends when the effective caps differ.
- **Self-healing.** The heartbeat is already on a timer, so a missed update
  corrects itself rather than needing its own retry.

The worker sends its caps over the existing delegation channel at attach
(`DelegateFrame::WorkerCaps`), and the daemon computes *effective* caps.

### What the worker's caps replace, and what they do not

Only **`permissions`** and **`has_input_permission`** — the two that are false
about the daemon and true about the worker, and the two the dashboard renders.

⚠️ NOT `codecs` / `hw_encoders` / `transports`. Measured on the MacBook
2026-09-01: both halves report **identical** values, so there is nothing to gain
— and the P2b-3 lesson argues against it anyway. The daemon is the half that
answers `rc:session.request`, so its resolution is what the server was told; if
the two ever diverged, advertising the worker's list while resolving with the
daemon's would produce exactly the class of bug P2b-3 was. Revisit only with a
measurement showing they differ.

### ⚠️ It must revert

When the worker detaches — logout, hand-back to launchd, a crash — the row must
go back to `no-gui-session`, or it claims a capture target that is gone and the
next session gets the black screen P2b just fixed. Reconcile, do not toggle:
compute effective caps from current state and send when they differ, the same
shape as [`crate::power::PowerKeeper`].

### Components

| where | change |
|---|---|
| wire | `AgentHeartbeat.caps: Option<AgentCaps>` |
| agent | `DelegateFrame::WorkerCaps`; effective-caps computation; send-on-change |
| server | accept caps on a heartbeat, update the hub's `AgentConn` and the `agents` row |
| UI | none — it already renders `permissions` |

## P2d — the installer stopped reverting P2 on every update

**P2 had a half-life of one release, and the release was the thing that ended
it.** `macos_supervisor::decide` stands down whenever
`gui/<uid>/fans.itachi.meshharbor.agent` is loaded — correctly, since the loser of that
race must be the supervisor rather than the enrolled agent. The `.pkg`'s
`postinstall` then re-bootstrapped that exact label unconditionally, so every
package update handed the GUI worker back to launchd and disarmed delegation.
The daemon's row went back to advertising a capture target it cannot serve, and
a controller connecting to it got the black-screen-with-working-input symptom
this FR exists to remove.

The operator's remedy (`launchctl bootout gui/<uid>/fans.itachi.meshharbor.agent`, which
the daemon's own log tells them to run) survived exactly until the next update —
and an update is precisely when nobody is watching.

Neither half was wrong on its own; nothing connected them. The supervisor knew
about the LaunchAgent, and the installer had never heard of the supervisor.

**The guard** (`agents/meshharbord/packaging/macos/postinstall`): when the root
daemon is opted in **and** its config carries
`macos_supervise_gui_worker = true`, the LaunchAgent is booted out and its plist
removed, and the daemon owns the worker.

- It reads the daemon's **own config** rather than a marker file of the
  installer's own. That key is the one `decide()` acts on, so the installer and
  the supervisor cannot disagree about who owns the worker; a marker would be a
  second source of truth for one fact.
- It **removes the plist** rather than merely skipping the bootstrap. A plist
  left in `~/Library/LaunchAgents` is loaded by launchd at the next login, so
  skipping alone would postpone the breakage by one login instead of ending it.
- ⚠️ It is **interlocked with the daemon opt-in**, and that interlock is the
  load-bearing half. Honouring the config key without a daemon to supervise
  would strip the LaunchAgent off a Mac that then installs no daemon either —
  no capture, no input, nothing to supervise. Only one of the six
  daemon × key states changes behaviour; the other five are today's path
  byte-for-byte.
- The dual-read behind the daemon opt-in is now **one function with two
  callers** (`daemon_is_enabled`). Two copies that drifted into disagreeing
  would produce exactly the stripped-worker Mac above — the same
  two-divergent-definitions shape that froze every managed role in FR-82.
- Booting the job out is **not a new hazard**: `replace_launchd_service` has
  always booted this label out as its first act. The change is that it is no
  longer bootstrapped back.

⚠️ `agents/meshharbord/packaging/macos/postinstall` had **no `.gitattributes`
rule**, only `core.autocrlf` on one developer's box. It has no extension, so
`scripts/*.sh` never matched it, and the rule written for the dpkg maintainer
scripts — *"`#!/bin/sh\r` … fails to configure on EVERY host"* — had no macOS
counterpart despite the identical failure mode under PackageKit. Pinned
`text eol=lf` alongside this change.

## Acceptance criteria

- [ ] A fresh install with **one** token produces **one** device row, and that row serves
      both a remote-desktop session and `meshharbor ssh`.
- [ ] `meshharbor exec <mac>` reaches root-owned paths **and** the GUI session's log from the
      same row (today this needs two different rows).
- [ ] After a reboot with **nobody logged in**, the Mac is present in `meshharbor peers` and
      `meshharbor ssh` works — the capability the daemon half exists for.
- [ ] A remote-desktop session started while logged in streams real pixels and accepts
      input, with `caps` reporting `has_input_permission: true` and **no TCC re-prompt**.
- [ ] `codesign -d -r-` on the bundle is byte-identical before and after the migration.
- [x] P2c: with a worker attached, the daemon's row reports `screen-capture` +
      `input` and the dashboard stops calling it "not a capture target".
      *Field-verified 2026-09-24 end to end — the daemon's send AND the row the dashboard
      renders from (field log). The daemon's own hello reports `no-gui-session`, so the
      row can only say otherwise through the P2c heartbeat path.*
- [ ] P2c: when the worker DETACHES, the row goes back to `no-gui-session`
      within one heartbeat — a stale "capture target" is worse than an honest
      "not one", because the next session gets a black screen.
- [ ] P2c: a device with no worker (every non-macOS agent, and a macOS one with
      the switch off) sends no `caps` on its heartbeats at all — measured on the
      wire, not inferred from behaviour.
- [x] P2d: a supervised Mac takes a package **update** and delegation is still
      armed afterwards — `gui/<uid>/fans.itachi.meshharbor.agent` is not loaded, the plist
      is gone from `~/Library/LaunchAgents`, and a session started after the
      update streams real pixels. This is the criterion the old build fails, so
      measure it on the CURRENT release first.
      *(2026-09-24, `agent-v0.4.100` — the first package update to reach a
      supervised Mac since P2d landed; the Mac took it unattended. After it:
      `launchctl print gui/501/fans.itachi.meshharbor.agent` → **`Could not find service`**;
      `~/Library/LaunchAgents` holds only `fans.itachi.meshharbor.desktop.plist` — **no
      `fans.itachi.meshharbor.agent.plist`**; a session started afterwards on the daemon row
      rendered **3024×1968** (native Retina), luma variance **3957** (a black frame
      reads ~0), **H.265** at **8 fps** with the bitrate counter live. Preconditions
      on the device: `macos_supervise_gui_worker = true`. ⚠️ **The fail half is the
      RECORDED pre-P2d observation**, not a fresh re-measurement: the P2d section
      above documents `postinstall` re-bootstrapping the label on every update and
      the black-screen-with-working-input result, which is why P2d exists.
      Re-creating it today would mean downgrading the operator's Mac to a pre-P2d
      build.)*
- [ ] P2d: a Mac with the daemon opted in but the supervise key **absent** takes
      the same update and keeps its LaunchAgent — the five unchanged states are
      what makes this safe to ship to every Mac, not just the supervised one.
- [ ] `kill -9` on the GUI worker respawns it within 10 s **without** the control WS
      dropping (measured: the device row never goes offline).
- [ ] An existing two-row Mac migrates to one row keeping its overlay address, and the
      retired row is tombstoned per `release_overlay_node`'s ordering (never re-issued).
- [ ] With the kill switch off, behaviour is byte-for-byte today's.

## Dead hypotheses — do not re-run these

1. **"The self-signed cert (FR-5) lets us merge the halves."** No. The cert fixed TCC
   *persistence* (a stable designated requirement across updates). The split is about
   *session access*. Orthogonal axes; merging was never gated on signing. What the cert
   *does* buy is that this refactor is now safe to attempt at all.
2. **"Windows merges them into one process, so macOS can."** Windows can only do it
   because of desktop attachment (`win_service/desktop.rs`). Absent that API, a session-0
   macOS daemon has no path to the screen — no entitlement, no TCC grant, nothing.
3. **"Run the daemon as the console user."** Loses root ⇒ no `utun`, no routes, no SSH
   server.
4. **"Run the agent as root inside the GUI session."** `/Library/LaunchAgents` jobs run
   as the console user; macOS has no root GUI agent.
5. **"Make the GUI half primary and give it a privileged helper."** Works while someone
   is logged in, and silently drops the mesh + SSH at the login window and on a headless
   reboot — a regression against what the daemon half exists for.
6. **"Pass the delegation channel as an inherited socketpair fd, so possession of the fd
   IS the authorisation."** Strictly better than a spawn-time secret — nothing to leak,
   no one-attached-worker bookkeeping, no new verb reachable by other processes, and the
   channel dies with the process. It does not survive P1's spawn chain: **`sudo` closes
   inherited descriptors**. Measured on the MacBook 2026-08-31 rather than read out of
   sudo's manual —

   | chain | fd 3 in the child |
   |---|---|
   | `launchctl asuser 501 <exe>` | **inherited** (`/etc/hosts`, 213 bytes) |
   | `launchctl asuser 501 sudo -u '#501' <exe>` | **gone** |

   Note the first row: `launchctl asuser` itself preserves fds, so this becomes available
   the day the chain drops `sudo` and drops privilege **in-process** instead — the
   machinery already exists (`RunAs::ConsoleUser`, `exec::apply_run_as`, P5). That is a
   real future simplification, but it would replace the identity mechanism that has only
   just been field-verified after costing an outage, so it is not a P2 dependency. Worth
   revisiting at P3, when the daemon owns the spawn unconditionally.

## Open decisions

- Spawn mechanism: `launchctl asuser` from the daemon vs a daemon-managed LaunchAgent
  (the postinstall already bootstraps into `gui/<uid>` — `packaging/macos/postinstall:108`).
- Migration: delete or tombstone the retired per-user row, and who initiates it.
- Whether the worker keeps a *dormant* enrollment as the P2 fallback, or is fully
  unenrolled from the start.

## Out of scope

Apple Developer ID / notarization (FR-7) · Windows and Linux, unchanged · the update half
`fans.itachi.meshharbor.update` (FR-5), which stays a separate root unit by design · the desktop
companion.

## Field-verification log

All of it on the operator's MacBook (Apple Silicon), driven
remotely — `meshharbor exec` for P0, `meshharbor ssh` on the daemon row from P1 onwards.

### 2026-08-30 — P0 spike: the mechanism works, and one half was never measured

From the running root daemon, a capture in session 0 fails with *"could not create image
from display"*. The same call through `launchctl asuser <console-uid>` produced an 8.4 MB
screenshot in **233 ms**, and our own binary spawned that way reported both a live GUI
session and its TCC grants — so the grants survive, which is what made P1 worth building.

**What the spike got wrong, and why:** it never measured the worker's *identity*. The
probe was `meshharbord caps`, which reports the GUI session and the TCC grants — both of
which root-in-a-session genuinely has — and says nothing about *which config* the process
would load. **A probe that shares a blind spot with the design confirms the design.**
`id -u` was the missing measurement, and it cost the outage below.

### 2026-08-30 — P1 (0.4.33) shipped, then took the Mac's remote-desktop half offline

`launchctl asuser <uid> <cmd>` joins the user's Mach bootstrap namespace but does **not**
change credentials — `launchctl asuser 501 id -u` prints `0`. Every spawned worker
therefore ran as root, resolved *root's* profile config, died instantly with
`no config found at /var/root/Library/Application Support/…`, and was respawned for as
long as the LaunchAgent stayed unloaded. Nothing bounded the ladder.

Fixed in **#1026** (0.4.34): `sudo -u "#<uid>"` — numeric, so no `getpwuid` lookup and no
wrong account when a uid has several names — plus `MAX_FAST_EXITS`, because a worker that
can *never* start is a configuration fault and hammering it hides the cause.

### 2026-08-30 — 0.4.34 re-test: privilege drop verified

Worker pid 4526 at **uid 501 (the console user, not root)**, parent 4525 = `sudo -u '#501'` at uid 0;
LaunchAgent confirmed not loaded; `permissions: ["screen-capture", "input"]`.
`kill -9` → respawned in ~14 s, again uid 501. Stand-down verified separately: with the
LaunchAgent loaded, `action=LaunchdOwns` and the user half's pid never moved.

Hand-back left an **orphan**: `stop_worker` killed only the direct child, so the agent
survived re-parented to launchd, held the single-instance lock, and launchd's own worker
exited *cleanly* on it — `KeepAlive{SuccessfulExit=false}` never retried. Turning the
supervisor **off** left the Mac running an unsupervised orphan nothing would restart.
A switch whose off position leaves the machine worse than either steady state is not a
kill switch. Fixed in **#1029** (0.4.35): own process group + group signal.

### 2026-08-31 — 0.4.35 re-test: #1029 confirmed, and it uncovered the other half

Precondition asserted first (`git merge-base --is-ancestor <fix> agent-v0.4.35`), because
"merged" is not "released" and "released" is not "installed".

The group structure, measured under supervision:

<!-- RETIRED-NAME-ANCHOR(5): verbatim `ps` output from the MacBook. The macOS
     bundle is deliberately NOT renamed — its name keys the TCC grants, so
     renaming it would drop Screen Recording + Accessibility on every Mac
     (FR-21). Rewriting the capture to the current name would make it a
     transcription rather than evidence. -->
```
25894     1 25894     0  meshharbor-agent   <- root daemon
34322 25894 34322     0  sudo            <- our child, OWN group (process_group(0))
34323 34322 34322   501  meshharbor-agent   <- worker, SAME group, uid 501
```

`sudo` does not `setsid` here (a separate probe showed a shell under `sudo -u "#501"`
carrying a pgid inherited from its ancestor), so `kill(-pgid, …)` reaches the whole
`launchctl → sudo → agent` chain and cannot touch the daemon. **No orphan survived.**

But the hand-back then left **no user half at all**:

```
22:58:03.902  user half:  WARN single-instance lock held by another process; exiting   <- exit 0
22:58:08.725  daemon:     INFO macOS supervisor: stopping our GUI worker group … pgid=34322
```

launchd starts its worker the instant the plist is bootstrapped; it hits our worker's
lock and exits **0**; up to `POLL` (5 s) later we notice `LaunchdOwns` and kill ours.

**The orphan and this are the same root cause seen from opposite ends: whoever loses the
single-instance lock exits 0, and `KeepAlive{SuccessfulExit=false}` never retries a clean
exit.** #1029 fixed *which side* loses; it did not make the hand-back complete. Fixed in
**#1039**: handing back is two steps, so it is its own `Action::HandBack(uid)` — stop our
group, then `launchctl kickstart` the LaunchAgent (without `-k`, so it is idempotent).

Separate hazard seen in the same window and filed as **#1040**, not fixed here: while
losing the lock race during the update, the user half logged
`rollback installer downloaded — spawning + exiting target=agent-v0.4.33`. Lock-conflict
exits can read as a crash loop to the rollback machinery, which would *downgrade* a
healthy host. This is why #1039 deliberately did **not** take the otherwise-obvious route
of making that exit non-zero.

### 2026-08-31 — 0.4.36: hand-back complete, P1 done

Same sequence, on a build carrying #1039. Takeover clean (worker uid 501 in its own
process group); bootstrapping the LaunchAgent back left **no orphan** *and* launchd owning
exactly one user half.

The log is the result worth keeping, because the race still fires:

```
00:09:01.773  user half:  WARN single-instance lock held by another process; exiting
00:09:02.424  daemon:     INFO macOS supervisor state action=HandBack(501)
00:09:02.424  daemon:     INFO stopping our GUI worker group ... pgid=71668
00:09:12.672  daemon:     INFO handed the worker back to launchd uid=501
00:09:17.684  daemon:     INFO macOS supervisor state action=LaunchdOwns
```

launchd's worker still loses the lock race and still exits 0; the kickstart is what brings
it back. A failure condition that reproduced and was recovered from is better evidence
than one that failed to occur.

Hand-back takes ~10 s end to end (SIGTERM, grace, SIGKILL, reap, kickstart), during which
the session has no user half. Bounded and self-healing; noted, not tuned.

**P1 is complete.** The switch stays default-off until P2 gives the daemon something to
delegate to.

### 2026-09-01 — P2b: the daemon's row streams real pixels

The goal of this FR, demonstrated on `agent-v0.4.43`. A session opened against the
**root daemon's device row** — session 0, no WindowServer, never able to show a
screen — streams the real desktop and accepts input, served by the GUI worker:

```
6a96be11  delegated  hevc_videotoolbox  viewer_age_ms 26, 5, 6
6a96bed9  delegated  hevc_videotoolbox  viewer_age_ms 5, 13, 8
6a96bf00  delegated  hevc_videotoolbox  viewer_age_ms 6, 8, 10
```

5–13 ms, indistinguishable from a direct session on the user's own row.

**The negative arm came for free.** Before delegation was armed, the same row gave a
black screen — and reproduced this FR's premise exactly:

```
WARN scrap capture unavailable — falling back to NoopCapture
     error=creating scrap::Capturer: other error
```

Session established, consent auto-granted, encoder running, ICE direct: everything
worked except the picture.

**Two bugs the field found and CI could not.**

1. **The delegated session was missing everything `Request` resolved** (#1137). First
   attempt: input worked — the operator unlocked macOS and dragged a window from the
   browser — and the screen stayed black. `Request` is not delegable, but it is the arm
   that RESOLVES the session and stashes seven values `SdpOffer` CONSUMES. `transport`
   defaults to `None` = the legacy RTP track, so the worker wrote 13 MB to a pipe the
   browser was not reading. The whitelist was chosen by asking which messages a session
   HANDLES; the miss was that one of them carries state another consumes.

2. **A latency finding that was NOT delegation** (#1152). 230–600 ms frame age vs 5–9 ms
   direct. Delegation and codec were perfectly confounded — every delegated session
   H.264 and slow, every direct one HEVC and fast — and breaking that needed one
   controlled run: among DELEGATED sessions, HEVC gives 5–13 ms and H.264 gives 139 ms.
   Ruled out first, each by measurement: ICE relay (`relay=false`, Host↔Host), the media
   path (`send_wait_avg 0.04 ms`, zero drops/errors), the daemon negotiating on weaker
   caps (both halves report identical caps), B-frame reordering (`max_b_frames(0)` is
   applied to every encoder). ⚠️ The UI auto-selected H.264, so the slow path was the
   DEFAULT.

⚠️ **Instrumentation lesson.** The delegation trace shipped at `debug!`, so the field
logs could not answer *"did it cross?"* — the first diagnosis had to correlate session
ids across two log files. Now `info!`, and the serving line should also carry
`session_id`: establishing WHICH sessions were delegated still took three queries.
A feature whose whole question is "did this reach the other side" must answer it at the
level the field runs at.

**P2b is complete.** P2c is next: the daemon's row still advertises `no-gui-session`, so
the UI presents it as "not a capture target" even though it now is one.

### 2026-09-24 — `agent-v0.4.100`: P2d holds through a real update (AC9)

P2d (#1553) had been CI-green for fifteen days and never met the event it exists for.
`agent-v0.4.100` was the first package update to reach this supervised Mac since, and it
arrived the way updates do — **unattended**. The daemon row went offline at 11:29Z,
the separately-enrolled `MacBook-1` row followed at 11:36Z, and the daemon
came back on 0.4.100.

| check, after the update | result |
|---|---|
| `launchctl print gui/501/fans.itachi.meshharbor.agent` | **`Could not find service`** — not loaded |
| `~/Library/LaunchAgents/` | only `fans.itachi.meshharbor.desktop.plist` (touched by this update) — **no `fans.itachi.meshharbor.agent.plist`** |
| a session started afterwards, on the daemon row | canvas **3024 × 1968**, luma variance **3957**, **H.265**, **8 fps**, bitrate counter live (95 → 93 kbps between reads) |
| `macos_supervise_gui_worker` | `true` — this is the supervised case AC9 names |

The second row going dark and **staying** dark is the other half of the same result: that
row *was* the LaunchAgent. Under the pre-P2d installer the update would have
re-bootstrapped it, the row would have come back, and the supervisor would have stood down
to `LaunchdOwns`. What remains is one row serving the session — the shape this FR exists for.

⚠️ **Watch-only, on purpose.** The session drove no input on the operator's machine, so
AC4's input half (`has_input_permission`, no TCC re-prompt) is **not** claimed here.
⚠️ **AC10 needs a second Mac** — one with the daemon opted in but the supervise key
*absent*, which must keep its LaunchAgent through the same update. This Mac cannot be
both halves.

### 2026-09-24 — P2c: the daemon's row reports the worker's permissions (end to end)

P2c shipped in `agent-v0.4.78` (#1458) and waited seventeen days for this. Two halves,
because each alone can lie:

| half | evidence |
|---|---|
| the daemon **sends** | its log, every connection: `announcing changed capabilities on the heartbeat (FR-43 P2c) permissions=Some(["screen-capture", "input"])` |
| the row **reports** | the dashboard's own data for MacBook-1-Daemon (`os: macos`, online): `permissions: ["screen-capture", "input"]`, `has_input_permission: true` |

🔑 **Why the second half is the one that counts.** The agent log proves only the send; a
broken `update_capabilities` on the server would leave that log identical while the row
kept saying `no-gui-session`. And the row value is self-discriminating: the daemon runs in
session 0, so its own **hello** reports `no-gui-session` on every connect — which is
exactly what this row showed before P2c (#971's step log after P2b shipped: *"the daemon's
row still advertises `no-gui-session`, so the UI presents it as 'not a capture target'
even though it now is one"*). The only path by which it can
read `screen-capture` + `input` is the P2c heartbeat → `update_capabilities` → the
dashboard. `permissionWarnings()` therefore renders no "No screen access" / "No input
access" chips, and the `no-gui-session` early return (the "not a capture target" branch)
does not fire.

⚠️ **The re-announcements are frequent, and that is correct.** The daemon announced these
same permissions 49 times across one 27-hour window — `last_announced_permissions` is
scoped to a *connection*, because a new connection's hello resets the row to
`no-gui-session` and P2c must restore it. Each one follows a fresh control connection, and
overnight those were the Mac surfacing from sleep: WireGuard's
`CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)` precedes them. That sleep is FR-55's, not this
FR's — and it turned out to be a real FR-55 defect (#1612).

⚠️ **Not claimed.** P2c's *revert* (row back to `no-gui-session` when the worker
detaches) needs a detach longer than one heartbeat: the two observed today
(`delegation channel closed` → `attached` at 11:50:35 and 17:50:43) lasted ~2 s, so no
heartbeat fell inside either, and a row that never needed to revert says nothing about
whether it can. The no-worker criterion asks for a **wire** measurement, and the absence
of a log line on another device is inference from behaviour, which it rules out. And
`has_input_permission: true` in the caps is only AC4's reporting half — that criterion
also needs real input accepted with no TCC re-prompt.
