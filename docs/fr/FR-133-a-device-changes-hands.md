# FR-133: A device changes hands — signing in from another organization offers to move it

> **Status:** in progress — claimed 2026-11-24. Tracking issue: none (GitHub Issues are disabled on
> this repository); this spec and its registry row are the record. The user chose option B on
> 2026-11-24 ("那就B").

## Goal

Signing out of the tray and signing in as someone from another organization today leaves the device
in the old organization: still online there, still controllable by its admins, absent from the new
person's list. A person who hands a computer on believes the account switch moved it.

When the person who signs in on a device does not belong to the device's organization, the device
asks: **"This device belongs to «A». Move it to your organization?"**
- **Move**: the device enrolls into the new person's organization (their approval, as any sign-in);
  its old organization's record is removed by the one removal sequence, with an audit entry and a
  notice to the old organization's admins ("moved to another organization by a person signed in at
  the device", naming no one from the other organization).
- **Keep**: today's behaviour, an account session only; the device stays where it is.
- A person who is a member of the device's organization is never asked.

## Key design

Full architecture, sequence diagram and security analysis live in [`docs/device-move.md`](../device-move.md).

- **Narrow removal route (`POST /api/agent/self/move`)**: `crates/modules/fleet/src/device_move.rs:208`.
  `POST /api/agent/self/unenroll` (`crates/modules/fleet/src/agent.rs:796`) keeps refusing permanent
  devices with 403. `self/move` requires both credentials (old agent JWT as bearer, new agent JWT in
  body), checks `pair_refusal` (`crates/modules/fleet/src/device_move.rs:69`: permanent personal
  non-temporary non-2FA old row; same `machine_id`, different tenant, non-ephemeral new row),
  claims the fresh (<10 min) consumed `device_login_requests` proof once via `claim_proof`
  (`crates/modules/fleet/src/device_move.rs:179`, indexed on `enrollment_jti`), removes the old row
  through `crates/modules/fleet/src/removal.rs:43` (`MOVED_REASON = "moved_to_other_org"`, no
  `rc:goodbye` per `removal.rs:114`), writes `device_move_audit`, and sends `NotificationType::DeviceMoved`
  to Org A's `MANAGE_AGENTS` holders without naming anyone or anything from Org B.
- **Kill switch**: `auth.native_device_move_enabled` (`MESHHARBOR__AUTH__NATIVE_DEVICE_MOVE_ENABLED`,
  default on); when off, `self/move` answers identically to `self/unenroll`'s 403.
- **Device & tray**: `crates/agent-core/src/device_move.rs` provides `offer_for` (`:127`),
  `move_refusal` (`:209`, refusing FR-127 `protected` and FR-129 `two-factor` before spending the
  token), `leaving_primary` (`:255`), `outcome_for` (`:309`, 404/405/403 older-server fallback), and
  `remove_old_row` (`:335`). Wired into the tray (`agents/meshharbor-desktop/src/tray.rs:1083`,
  `agents/meshharbor-desktop/src/commands.rs:871-965`), `mh login --replace` / `enroll --replace`
  (`agents/meshharbord/src/main.rs:1438`, `:3697`, `:3853`), and `enroll-personal-system`
  (`agents/meshharbord/src/personal_system_exec.rs:130`, `:176`, `:214`). `GET /api/agent/self/devices`
  (`crates/api/src/routes/agent_self.rs:301`) exposes `org_name` for permanent devices only;
  `NodeStatus.two_factor` (`crates/localapi/src/lib.rs:211`, `agents/meshharbord/src/localapi_state.rs:703`)
  lets the tray refuse two-factor devices upfront alongside `protected`.

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P1 | Server: a device moved by a person-approved enrollment of the same machine into another org removes its old row (removal sequence, audit, admin notice) | `auth.native_device_move_enabled` (off = 403 as today) | built (tests passing; pending release & field) |
| P2 | Tray: detect the other-org sign-in, ask, move or keep | — | built (tests passing; pending release & field) |
| P3 | `mh login --replace` uses the same removal | — | built (tests passing; pending release & field) |
| P4 | Docs (`docs/device-move.md`, `docs/multi-org.md`, `docs/README.md`) | — | built |

## Acceptance criteria

- [x] **AC1.** Sign-in by a member of the device's org: no prompt, nothing changes (tests: `crates/agent-core/src/device_move.rs::tests::a_move_is_offered_only_to_a_non_member_of_a_permanent_personal_device`, `agents/meshharbor-desktop/src/commands.rs::tests::a_move_is_offered_only_to_someone_outside_the_devices_org`).
- [ ] **AC2.** Move: the device is in the new org, gone from the old org's list, the old org's audit has
  the entry and its admins the notice; the overlay lease is released by the normal sequence (tests
  pass in `crates/tests/src/device_move_tests.rs`; field verification pending).
- [x] **AC3.** Keep: identical to today (tests: `offer_for` / `move_offer_from` and `tray::offer_move` Keep branch + kill-switch/older-server fallback in `device_move_tests.rs`).
- [x] **AC4.** A device cannot remove its old row without a person-approved enrollment of the same
  machine elsewhere; a plain `self/unenroll` of a permanent device is still 403 (tests: `crates/tests/src/device_move_tests.rs`).
- [x] **AC5 (docs).** The enrollment/multi-org docs describe the move (mermaid, anchors in [`docs/device-move.md`](../device-move.md) and [`docs/multi-org.md`](../multi-org.md)) and a row in
  [docs/README.md](../README.md).

## Out of scope

Temporary (invitation) devices keep `mh leave`. Secondary org enrollments stay as they are.

## Field-verification log

| When (UTC) | What | Result |
|---|---|---|
