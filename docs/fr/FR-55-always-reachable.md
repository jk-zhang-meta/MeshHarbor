<!-- SPDX-License-Identifier: MPL-2.0 -->
# FR-55: A device stays reachable instead of quietly sleeping

**Status:** P0 measured, P1 + P2 shipped (`agent-v0.4.45` / `0.4.46`), P3 deferred on
evidence and then built under FR-97 P3b (2026-10-17, the last section), P4 + P5 open — and ⚠️ **P2's AC-power arm FAILS in the field**: a Mac that
falls asleep on battery and is then plugged in stays asleep all night with our
assertion held (2026-09-24, field log). This line read "proposed" until then, with the
field log empty, while P0–P2 had shipped and been measured — the record below restores
that history. Tracking issue: [#1154](https://github.com/jk-zhang-meta/MeshHarbor/issues/1154). Anchors verified against
master `40da643d`.

## Goal

An enrolled device is reachable when the operator needs it — mesh, remote desktop, SSH
and exec — instead of dropping off the fleet because the OS decided to sleep, with
nothing anywhere saying why.

Pillar 2's acceptance bar is *"just works"* on an unmanaged laptop as well as a managed
desktop. A device that is unreachable half the day does not meet it, and today **nothing
in the product has an opinion about power at all.**

## Field evidence

Reported by the operator on 2026-09-01 ("meshharbor going offline after a while"), then
measured on the MacBook.

**The machine really does sleep, on AC, with the lid open and closed:**

```
10:33:22  Entering Sleep state due to 'Idle Sleep':TCPKeepAlive=active Using AC (Charge:100%)
15:00:56  Entering Sleep state due to 'Clamshell Sleep':TCPKeepAlive=active Using AC (Charge:100%)
```

**Its idle timer is one minute** (`pmset -g`): `sleep 1`, `hibernatemode 3`, `standby 1`,
`disksleep 10`. Also `tcpkeepalive 1` and `womp 1` — both relevant below.

**Nothing we do holds it awake.** `pmset -g assertions` shows only `powerd` and
`WindowServer`. The single `meshharbord` mention is

```
pid 399(WindowServer): UserIsActive named:
  "com.apple.iohideventsystem.queue.tickle.nxevent service:IOHIDSystem pid:36743 process:meshharbord"
```

which is a **byproduct of injecting input during an active remote session**, not a
deliberate assertion. ⚠️ It therefore protects a session where someone is *typing*, and
not a view-only one — the case where an operator is watching a long build is exactly the
case that sleeps.

**And the codebase confirms it**: `IOPMAssertion`, `SetThreadExecutionState`,
`PowerCreateRequest` and `systemd-inhibit` have **zero** occurrences across
`agents/` and `crates/`.

## What is actually forced, and what is ours

Worth separating before designing, because one of these cannot be fixed:

| | forced by the OS | ours |
|---|---|---|
| A sleeping machine cannot serve a WS | ✅ | |
| macOS **clamshell** sleep ignores idle-sleep assertions on a laptop with no external display | ✅ | |
| Nothing asks the OS to stay awake | | ✅ |
| An active session does not hold an assertion | | ✅ |
| "Offline" and "asleep by policy" look identical to an operator | | ✅ |

So the honest framing is **two families of answer**, and a complete feature needs both:

1. **Do not sleep** — hold a power assertion while it matters.
2. **Wake it** — a mesh peer on the same L2 sends a magic packet. `womp 1` is already on
   here, and the overlay already knows which peers share a LAN.

Neither alone is sufficient: (1) cannot beat clamshell sleep or an operator who closes
the lid, and (2) needs a peer on the same segment.

## Key design

### Per-OS mechanism

- **macOS** — `IOPMAssertionCreateWithName`. Two candidate types, and they are not
  interchangeable: `kIOPMAssertionTypePreventUserIdleSystemSleep` (idle only) and
  `kIOPMAssertionTypeNetworkClientActive`, which exists precisely for "this machine is
  serving the network". ⚠️ Neither defeats **clamshell** sleep — that is an OS limit, and
  the feature must SAY so rather than appear not to work.
- **Windows** — `PowerCreateRequest` + `PowerSetRequest(PowerRequestSystemRequired)`, not
  `SetThreadExecutionState`: the latter is per-thread and unreliable from a service, which
  is exactly how `meshharbord` runs on a fleet host.
- **Linux** — logind `Inhibit()` over D-Bus (`what="sleep"`, `mode="block"`), holding the
  returned fd for as long as the inhibition should last. ⚠️ Headless servers rarely sleep,
  so this matters for desktops; and `mode=block` is a request a policy can override.

### Default OFF, and honest about it

⚠️ **Preventing sleep on a battery-powered laptop is user-hostile**, and a remote-access
tool that silently drains a battery deserves the reputation it gets. So:

- a device-owned config key, default **off** — the same last-word rule as `exec_enabled`
  and `ssh_enabled` (`docs/remote-config.md`);
- an obvious refinement to decide, not assume: **on AC only** as the middle setting;
- an **active session** should hold an assertion regardless of the standing policy — a
  session must not be cut by an idle timer. Today that happens by accident on macOS, and
  only while input flows.

### Say why the device is gone

⚠️ Today "offline" is one word covering *crashed*, *network died*, *powered off* and
*asleep by policy*, and each has a different fix. The device should report its power
policy and whether an assertion is currently held, so the dashboard can distinguish them.
This is the `Some([])` vs `None` lesson from the overlay ACL and `ssh_activity`'s
"empty ≠ inactive", recurring on a third surface — see FR-49, where five surfaces all
reported normally while a feature was dark.

## Phases

| P | Scope | Kill switch |
|---|---|---|
| P0 | **Measure first.** How often do fleet devices go offline, and does it correlate with sleep rather than crashes or network? Build nothing until the answer is known. | n/a |
| P1 | An **active rc/ssh session** holds an assertion, on all three OSes. Narrow, always-correct, no policy needed. | per-OS: assertion failure is logged and non-fatal |
| P2 | Standing policy `power_policy = never \| on-ac \| always`, default `never`, device-owned. macOS first. | the key itself; absent ⇒ today's behaviour |
| P3 | Windows + Linux implementations of the same policy. | as P2 |
| P4 | Report it: `meshharbor status` + the dashboard distinguish "asleep by policy" from "offline". | additive, read-only |
| P5 | **Wake on LAN from a mesh peer** — an awake peer on the same L2 sends the magic packet on request. | server-side switch; off by default |

## Acceptance criteria

- [ ] P0 produces a number: what share of fleet offline-time is sleep, measured, not assumed.
- [ ] With a remote-desktop session open and **no input for 10 minutes**, the device does
      not sleep — on macOS, Windows and Linux.
- [ ] With `power_policy = never` (the default), behaviour is byte-for-byte today's: no
      assertion is taken, and `pmset -g assertions` / `powercfg /requests` show nothing
      from us.
- [ ] With `power_policy = on-ac`, a laptop on battery still sleeps and the same laptop on
      AC does not.
- [ ] An operator looking at a device that is asleep by policy can tell that from the UI,
      without reading a log.
- [ ] ⚠️ The macOS **clamshell** limitation is documented in the UI where the policy is
      set — not discovered by a user whose lid-closed Mac still vanishes.
- [ ] P5: a sleeping device on the same LAN as an awake peer can be woken from the
      dashboard, and the audit says who did it.

## Open decisions

- Does the standing policy belong in `DesiredConfig` (server-pushable) or stay strictly
  device-owned? Pushing it means an org admin can drain an employee's battery; not
  pushing it means the last gate is again the one nobody can reach — the exact tension
  `docs/remote-config.md` resolves with `remote_config_enabled`.
- Is `NetworkClientActive` or `PreventUserIdleSystemSleep` the right macOS type? The
  former is semantically exact and may behave better with Power Nap; needs measuring.
  **Half-answered by measurement, 2026-09-24: `PreventUserIdleSystemSleep` is NOT
  sufficient.** It governs the idle timer during a *full*, user-driven wake and nothing
  else. It has no power over a system in a transient (dark / notification / maintenance)
  wake returning to sleep — and a Mac that dozed off on battery lives in exactly those
  wakes after it is plugged in. macOS logged ~59 such returns to sleep on AC in one night
  with our assertion held and confirmed present (field log). The replacement is still
  open and still has to be MEASURED, in the one scenario that failed:
  `NetworkClientActive`, or `PreventSystemSleep` (honoured only on AC, which is
  exactly `on-ac`'s semantics). ⚠️ Do not pick one from documentation — this module
  already chose once on "well understood" and it was wrong in the most ordinary case.
- Should an **exec** run hold an assertion? A 40-minute build kicked off by `meshharbor exec`
  has the same problem as a session, and the same answer is not obvious.

## Out of scope

- Waking a device that is off (as opposed to asleep) — that is BIOS/AMT territory.
- Battery-life optimisation generally.
- Scheduled wake (`pmset repeat`), which is an operator's own configuration.

## Field-verification log

⚠️ This section read *"empty — P0 has not run"* until 2026-09-24, while P0 had been
measured and P1/P2 shipped and field-verified on 2026-09-01. The first two entries are
restored from #1154's comments, where that evidence had lived alone for three weeks.

### 2026-09-01 — P1 + P2 shipped in `agent-v0.4.45`, field-verified on the MacBook

Precondition asserted first: `git merge-base --is-ancestor c0287753 agent-v0.4.45`.

| # | arm | assertion | result |
|---|---|---|---|
| 1 | **control** — default policy | we hold nothing | ✅ 0 assertions |
| 2 | typo at set time | refused, not coerced | ✅ `power_policy must be one of never \| on-ac \| always (got "alwyas")` |
| 3 | `on-ac` on mains | held, by **policy** | ✅ `session_active=false` |
| 4 | flip to `never` | released | ✅ back to 0 |
| 5 | back to `on-ac` | held again | ✅ |

⚠️ **Every arm ran with the Mac already awake.** Row 3 proved we *take* the assertion
on AC; nothing proved the assertion *keeps the Mac awake* — see 2026-09-24.

### 2026-09-01 — P0 measured: the Linux fleet does not sleep, so P3 is deferred

`/sys/power/state` offers `freeze mem disk` on mars, jupiter and zeus, but `IdleAction`
is unset on all three, and uptimes were 6 weeks, 6 weeks and **25 weeks** — a host up
25 weeks has not been idle-suspending. P3 (logind `Inhibit()` over D-Bus) would put a
D-Bus stack into every Linux agent for no measured benefit. Deferred, not cancelled: the
case it exists for is a Linux *desktop*, which the fleet does not have.

Left open that day, needing a human: the **battery** arm, and a **session overriding
`never`**.

### 2026-09-24 — the battery arm passes; the AC arm FAILS

Found while field-verifying FR-43 P2c: the daemon row re-announced its capabilities
every 30–60 minutes overnight, each time right after WireGuard reported
`CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)` — nine silent minutes, i.e. the machine had
been asleep. The daemon's own log said it was holding the Mac awake the whole time.
macOS's power log (`pmset -g log`) is the surface that settles which is true.

**Battery arm — passes**, and needed no human after all: it happened on its own.

| evidence | source |
|---|---|
| 09-23 00:33:36 (+0300) `Entering Sleep state due to 'Idle Sleep' … Using Batt (Charge:76%)`, keeper **not** holding | `pmset -g log` |
| 09-24 18:28:30Z `power: released the device to sleep normally policy="on-ac"` | daemon log |
| afterwards: `Now drawing from 'Battery Power'`, `PreventSystemSleep 0`, **no** meshharbord assertion listed | `pmset -g batt` + `-g assertions` |

**AC arm — fails.** One night, second by second (`pmset` times are the Mac's `+0300`):

| time | event |
|---|---|
| 00:33:36 | `Idle Sleep`, **on battery** — correct under `on-ac` |
| 00:34:30 | `DarkWake to FullWake … due to Notification Using AC` — the charger goes in |
| 00:34:34 | keeper: `holding the device awake policy="on-ac" on_ac=Some(true) session_active=false`; macOS: `PID 72979(meshharbord) … PreventUserIdleSystemSleep "meshharbor: keeping this device reachable"` |
| 00:34:41 | `Notification Wake Back to Sleep` — **seven seconds later, assertion held** |
| 02:18:05 | the **same** assertion (`id 0x10000954c`) still present, age `01:43:30` |
| to 11:35 | no FullWake ever again; the Mac surfaces only in DarkWakes |

Inside the window the keeper logged as holding (00:34:34 → 11:41:30), macOS returned to
sleep **47 times — all 47 on AC**: 27 `Maintenance Sleep`, 18 `Sleep Service Back to
Sleep`, 2 `Notification Wake Back to Sleep`. **Zero** were `Idle Sleep`, and zero were
`Clamshell Sleep` — so this is **not** the documented lid limitation.

🔑 **Why it fails.** `PreventUserIdleSystemSleep` stops the *idle timer* during a full,
user-driven wake. It has no say over a system in a transient wake going back to sleep —
and a Mac that dozed off on battery is in exactly those wakes after it is plugged in.
So the assertion is real, present, and irrelevant, and the keeper's log line *"holding the
device awake"* is a claim about the device that the device contradicts.

The following day and night corroborate it from the daemon's side, more weakly: the
keeper logged one continuous hold from 09-23 08:52:50Z to 09-24 11:50:36Z, and inside it
the daemon re-announced its capabilities **49 times** — each one a fresh control
connection. The overnight ones I inspected follow the same sleep tell. `pmset` was not
pulled for that window, so it supports the finding rather than proving it a second time.

🔑🔑 **Why 2026-09-01 did not catch it.** Every arm began with the Mac awake, so it tested
whether we take the assertion, never whether the assertion keeps anyone reachable. The
scenario that matters most — lid open, battery flat by evening, plugged in at night — is
the one path the test could not enter. *A hold is not a wake.*

⚠️ **P1 (a session holds the machine) is not refuted by this**, and the reason is *when*
the assertion is taken, not how. A session can only begin while the Mac is reachable,
i.e. in a full wake — the one state where `PreventUserIdleSystemSleep` does its job. The
standing policy acquires on an AC *transition*, and plugging in a dozing laptop delivers
that transition during a transient wake, where the same assertion is inert. So the
failure is specific to P2 — the case with nobody connected, which is the case FR-55
exists for. (Not claimed: that a session is otherwise protected. Input injection tickles
`IOHIDSystem` only while someone is typing; a view-only session or an SSH session gets
nothing from it — see `power.rs`'s module doc.)

### 2026-10-17 — P3 built under FR-97 P3b: both reasons for the deferral are gone

The 2026-09-01 deferral rested on two facts, and neither holds any more.

- **D-Bus is already in every Linux agent.** `zbus` comes with `portal-capture`, which
  `full`, and so every shipped Linux build, now carries (FR-45, FR-93). The inhibitor adds
  no dependency.
- **The fleet has Linux desktops.** FR-93 put GNOME and KDE desktops in it, and a desktop
  idle-suspends, which is the case P3 exists for.

So P3 is built as designed above: logind `Inhibit()` with `mode="block"`, the fd held for as
long as the keeper wants the machine awake (`agents/meshharbord/src/power.rs`, the Linux
`imp`). It runs from a plain thread, because zbus's blocking API panics inside the tokio
runtime the keeper runs on. `what` is `sleep:idle` for a root daemon. A per-user daemon
runs outside every login session, where logind's polkit policy grants only `idle`
(`inhibit-block-sleep` is `allow_any=no`), so it takes `idle` and logs why. The design
and the field record are in FR-97 (`docs/fr/FR-97-os-feature-parity.md` §3.8, §8) and
`docs/remote-control.md` §5.1d.
