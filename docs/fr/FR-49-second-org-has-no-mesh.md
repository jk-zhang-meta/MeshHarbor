# FR-49: A second org gets no mesh, and every surface reports normally

**Issue:** [#1084](https://github.com/jk-zhang-meta/MeshHarbor/issues/1084) ·
Status: **P1–P3 implemented, field-verified** (2026-08-31) · Found while enrolling four demo devices for
[FR-41](FR-41-product-demo-recording.md) (#965).

## Goal

A device enrolled into a second organization should either **be on that org's
mesh**, or **say that it is not**. Today it is neither: `overlay_mode` is forced
to `Off` at enrolment with no way to change it short of hand-editing
`config.toml`, and five separate surfaces report the device as healthy.

## Root cause, with anchors

`crates/agent-core/src/enrollment.rs:340` — every appended org, unconditionally:

```rust
let mut entry = crate::config::OrgEntry {
    label: label.clone(),
    ...
    enabled: true,
    overlay_mode: crate::config::OrgOverlayMode::Off,
```

`agents/meshharbord/src/main.rs:1791-1731` — `--overlay` exists, and sets the
**primary's** flag regardless of which identity was just enrolled:

```rust
if overlay && !cfg.overlay_enabled {
    cfg.overlay_enabled = true;
    tracing::info!("overlay participation enabled by --overlay");
}
```

So `meshharbord enroll --server B --token … --overlay` on a device already enrolled
in A appends org B with `overlay_mode = Off`, and turns on (or re-confirms) the
overlay for **A**. The flag reads as granted and applies to the wrong org.

## Why nobody notices: five surfaces, all normal

This is the part that makes it worth an FR rather than a one-line fix. The
device is genuinely, silently absent from the second org's mesh, and:

| Surface | What it shows | What it omits |
|---|---|---|
| `meshharbord enroll` output (`main.rs:1766`) | "Enrolled into an ADDITIONAL org as …" + "manage them with `meshharbord org ls`" | any mention of the mesh |
| `meshharbord org ls` (`main.rs:1945`) | LABEL · PRIMARY · ENABLED · ORG · SERVER | **no overlay column** |
| `mh status` (`localapi::OrgStatus`) | label · agent id · enabled · connected · stopped · update-ignored | **no overlay field** — the org's WS *is* connected, so it reads healthy |
| `mh peers` (`localclient.rs:1398`) | one `── org: <label> ──` section per org **that has peers** | an overlay-off org produces **no section at all** — identical to an org whose peers are simply offline |
| the dashboard | the device row, online | it is the server's view; the server was never told |

The device is online in both orgs, answers exec and SSH in both, and has no mesh
in one. Every indicator the operator has says it is fine.

⚠️ This is the `Some([])` vs `None` distinction the overlay ACL work already
paid for once (`ingress_rules`: `None` = no ACL, `Some([])` = deny — *never*
collapse them), and the same lesson as `ssh_activity`'s **"an empty result is
not evidence of inactivity"**. An org with no mesh and an org with no peers yet
must not render identically.

## And there is no supported way to turn it on

`meshharbord org` offers `ls · rm · enable · disable · set-primary`
(`main.rs:555-576`). None of them touches `overlay_mode`. The only path is to
open `config.toml` — the file that also holds the agent token and the SSH host
private key, is written atomically with a `.prev` sibling, and on Windows lives
under a machine-global ACL-restricted directory. Hand-editing it is not a
supported operation, and a partial write there is the documented
ALL-NUL-corruption class.

## Key design

Three phases, smallest first. **P1 alone closes the reported harm** — the device
still has no mesh, but the operator is told, which is the difference between a
five-minute fix and the two days this cost in the field.

### P1 — say it

- `OrgStatus` gains `overlay_mode: String` (wire-additive; empty from an older
  daemon, exactly as `PeerInfo.org` already handles this).
- `mh status` prints it per org.
- `meshharbord org ls` gains an `OVERLAY` column.
- `mh peers` prints a section for an **enabled** org whose overlay is off,
  saying so, instead of omitting it. An org with an overlay and no peers keeps
  its existing empty section — the two states must be distinguishable, which is
  the whole point.

### P2 — make it settable

- `meshharbord org overlay <label> <off|netstack|tun>`, persisted through the same
  `config::save` every other `org` verb uses.
- `enroll --overlay` applies to **the identity actually being enrolled**: the
  primary flag on a primary outcome, that org's `overlay_mode` on an
  `AppendedOrg`/`RefreshedOrg`.
  - ⚠️ Keeps the existing one-way invariant: `--overlay` only ever turns an
    overlay **on**. A re-enrolment must never drop a host out of a mesh it had
    joined (`enrollment.rs`'s merge protects the same property).
  - ⚠️ What mode does `--overlay` mean for a secondary? `tun` requires the
    primary's shared-adapter path (`overlay_multi_org`, `overlay_tun_per_org`)
    and refuses on macOS (`SystemTun::add_address_sync`); `netstack` needs no OS
    privilege at all. Resolved in P2, not assumed here — see Open decisions.

### P3 — scope the output

- `mh peers --org <label>`, and the same on `status`.
- Motivation is not only ergonomics: on a device enrolled in a customer org and
  a personal one, `peers` prints **every** org's node names together, and there
  is no way to show one. During FR-41 that made the command unusable on camera,
  and it is the same problem for anyone sharing a screen or filing a bug report.

## Phases

| # | Phase | Kill switch | Status |
|---|-------|-------------|--------|
| P1 | Report `overlay_mode` in `org ls`, `status`, `peers` | read-only; nothing to disable | **shipped** |
| P2 | `org overlay <label> <mode>` + `--overlay` targets the enrolled identity | the verb is opt-in; `--overlay` stays one-way | **shipped** |
| P3 | `peers --org` | flag absent = today's output byte-for-byte | **shipped** (`status --org` dropped — the enrollment block is short and complete, so a filter would hide context rather than reduce noise) |

## Acceptance criteria

- [ ] on a device in two orgs, `meshharbord org ls` shows each org's overlay mode
- [ ] `mh status` shows it per org
- [ ] `mh peers` renders an overlay-off org **differently** from an org with
      an overlay and no peers — verified by producing both states on one device
- [x] `meshharbord org overlay <label> tun` puts the device on that org's mesh after
      a restart, verified by a ping across it *(FR-97 P1d, 2026-10-18 on
      0.4.143: a Mac's secondary on a utun of its own, the org's anchor 5/5;
      FR-97 §8)*
- [ ] `enroll --overlay` into a second org enables **that** org, and leaves the
      primary's flag untouched
- [ ] `enroll` without `--overlay` on an org that already had one does not turn
      it off (regression lock on the one-way invariant)
- [ ] `mh peers --org <label>` prints only that org
- [ ] an older daemon reporting no `overlay_mode` renders as it does today, not
      as "off" (absent ≠ off — the same trap as an absent age reading 0 ms)

## Out of scope

- **Server-side visibility.** The dashboard cannot show this: `overlay_mode` is
  device-owned and deliberately not in `DesiredConfig`. Surfacing it would need
  the device to report it (the `rc:agent.config_status` shape), which is a real
  follow-up but a different mechanism and a different gate.
- **Changing the default.** A secondary org defaulting to `Off` is defensible —
  joining a second mesh has host-global consequences (routes, DNS, a shared
  adapter) and the device owner should opt in. This FR makes the default
  *legible*, it does not argue with it.
- **`overlay_multi_org` / `overlay_tun_per_org` mechanics.** Shipped and default
  ON since rc.339; unchanged here.

## Open decisions

- **What mode `--overlay` selects for a secondary.** Candidates: mirror the
  primary's mode; always `netstack` (no OS privilege, cannot wedge a host);
  require an explicit `--overlay-mode`. Leaning `netstack` for the flag and the
  explicit verb for anything else — a flag that silently installs routes on a
  host is the failure mode "never self-wedge" exists to prevent.
- **Whether `status --org` is worth it** or `peers --org` alone covers the need.

## Field-verification log
### 2026-08-31 — on this box's real two-org config, and against the LIVE (older) daemon

`meshharbord org ls` on a genuinely multi-org device now carries the column:

```
LABEL          PRIMARY   ENABLED  OVERLAY   ORG (tenant)               SERVER
primary        yes       yes      tun       69a1dbba…                  https://meshharbor.itachi.fans
jovanov                  yes      tun       6a712a57…                  https://meshharbor.itachi.fans
```

and on a config holding a dark org it says so in words as well as in the column:

```
acme                     yes      off       2222…
beta                     yes      netstack  3333…

note: 1 enrolled but NOT on the mesh (overlay off): acme
      `meshharbord org overlay <label> netstack|tun` joins one; restart the daemon to apply.
```

`mh status` grew the block it never had — `NodeStatus.orgs` had been on the
wire since multi-org P1 and was rendered by NOTHING but `--json`:

```
  enrollments
    primary        connected, overlay ? (primary)
    jovanov        connected, overlay ?
```

⚠️ **That `?` is the absent≠off criterion verified for free, against a genuinely
older daemon** — the live one does not send `overlay_mode`, and the new CLI
prints "unknown" rather than asserting the claim it never made.

`peers --org` scopes to one enrollment (2 sections → 1), and an unknown label
answers `No enrollment labelled "nosuch" — see \`meshharbord org ls\`.`

Every refusal on the new verb was exercised and none of them wrote anything:

| input | result |
|---|---|
| `org overlay beta tunn` | `unknown overlay mode "tunn" — expected one of: off, netstack, tun` |
| `org overlay primary tun` | refused, names `overlay_enabled` as the right knob |
| `org overlay nosuch tun` | `no org labelled "nosuch" — see \`meshharbord org ls\`` |

**The regression lock is falsifiable**: restoring the old `apply_overlay_flag`
(always set the primary) makes
`overlay_flag_enables_the_org_that_was_actually_enrolled` fail. ⚠️ The other
three overlay-flag tests still PASS against the broken version — they lock
adjacent properties, and only that one catches the defect.

### Not field-verified

- **The `peers` dark-org section** cannot fire against a daemon that predates
  the change (it reports no `overlay_mode`, and absent is deliberately not
  `off`). Its selection is locked as a pure function instead —
  `only_an_enabled_overlay_off_org_with_no_peers_is_dark` — covering all four
  exclusions. Real proof needs a release.
- **`org overlay … tun` actually joining a mesh**, which needs a daemon restart
  on a two-org host.

### After close: a netstack secondary joined nothing (#2493)

FR-97 P1d ran this FR's own flow on 0.4.143 and found the gap. `enroll
--overlay` into a second org picks `netstack`, and that org joined **no** mesh:
`AgentConfig::for_org` turned a secondary's overlay on for `tun` only. The
check dates from #340, and #381 kept it when it made netstack per-org.
Meanwhile `status` read `overlay netstack`, the very "reports normally" this FR
set out to end.

`org overlay … tun` was verified on a Mac in the same run: a utun of its own,
and the anchor answered 5/5 through it.

The fix, with the operator's two decisions:
1. A netstack secondary joins with its own port and key alone, so the
   same-control-plane rule is dropped for it, since it opens no adapter.
2. A missing port is picked free, at enroll, at `org overlay … netstack`, at
   a pushed join, and at daemon start for an entry written before the fix.

Detail: `docs/multi-org.md`, the netstack paragraph.

Field red → green on Linux, 2026-10-19. The host was a throwaway `ubuntu:24.04` container on mars with one root
daemon. Its primary was in an org with no overlay, and its secondary was enrolled into the anchor's org with
`--overlay`. Both rows were standard enrollments, deleted afterwards.

| build | the secondary's front, 45 s after start | `peers --org a` | through the front |
|---|---|---|---|
| 🔴 released 0.4.143 | the enroll left no port, so 10800 was set by hand; **nothing listened on it**, and `status` still said `overlay netstack` | no peers | `connect: Connection refused`, at the front itself |
| 🟢 this fix (a release-profile build with `overlay-l3,overlay-netstack,ssh-server`) | the enroll picked 10800 and printed it; it listened | 9 peers, the anchor `direct` | a CONNECT to the anchor's `:22` was refused in 0 ms, a reset over the mesh, while an unassigned address in the block timed out after 15 s; the anchor's MagicDNS answered an A query for its own name with its overlay address |

The front answers REP 4 for every failed connect, so the TIME is what tells a refusal from no path: the netstack
fails at once only on a reset, and waits out its 15 s connect timeout otherwise.

Shipped in 0.4.145. The same container check passed on its candidate (release run 39248610025) and on the
published release, which carries the candidate's binary, and #2493 was closed (2026-10-19).

