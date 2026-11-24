# FR-130: The session outlives its control socket — a server restart no longer ends a remote-control session

> **Status:** in progress — claimed 2026-11-24; P1–P3 implemented and verified by automated tests,
> P4 field verification pending. Tracking issue: none (GitHub Issues are disabled on this
> repository); this spec and its registry row are the record. A port of upstream roomler-ai's
> FR-138 (`docs/fr/FR-138-the-session-outlives-its-control-socket.md` at upstream `eb96522a3`), which
> is closed there with every criterion met.

## Goal

A server restart, or any other loss of a device's control socket while the device stays up, no
longer ends a healthy remote-control session. The person at the viewer sees no new session, no new
consent prompt and, on a direct or TURN carrier, no gap in the picture. Every guarantee stays: the
server still decides who may control the device, a kick still lands, and every WebRTC peer that
really ends is still closed.

## Why here

- Every web-UI cutover on production rebuilds the app container: the API restarts for about 25 s
  (measured 2026-11-24 00:30Z), so every live session ends and its viewer redials as a new session
  6–24 s later, with a new consent prompt where the device asks.
- FR-128 puts a restricted-zone device's control socket through its zone gateway; a gateway update
  or a cross-border wobble drops it the same way.

## Design summary

The full engineering record — state diagrams, wire compatibility matrix, MeshHarbor-specific
invariants (file-child revocation, strict zone routes, device shares, FR-127/FR-128/FR-129, Mac
delegation), and operator runbook — lives in [remote-control.md §11.11](../remote-control.md#1111-a-session-outlives-its-control-socket-fr-130),
[multi-pod-scale-out.md](../multi-pod-scale-out.md#a-live-rc-session-through-its-pods-death-fr-130),
and [deployment.md](../deployment.md#a-roll-and-a-live-remote-session-fr-130).

Key anchors:

| Layer | Responsibility | Anchors |
|---|---|---|
| Wire & model | `rc-resume` verb (`RpcCap::RcResume`), `kept_sessions` on `AgentHello`, `rc:agent.resume_window`, `rc:session.detached`, `rc:session.resumed`, `rc:session.rejoin`, `replaces` on `rc:session.request`; `RemoteSession` detach/fence fields (`detached_at`, `resume_by`, `attach_seq`); `AuditKind::{SessionDetached, SessionResumed}` | `crates/remote_control/src/signaling.rs:2206`, `:4187`, `:4193`, `:4204`; `crates/remote_control/src/audit.rs:247` |
| Server config & scope | `rc.session_resume_secs` (`MESHHARBOR__RC__SESSION_RESUME_SECS`, default **0 = off**, capped at 120 s); `rc_resume_scope` collection + `GET`/`PUT /api/admin/rc-resume-scope` live re-announcement | `crates/config/src/settings.rs:1116`; `crates/modules/fleet/src/resume_scope.rs:255`, `:377` |
| Hub & lifecycle | Detach on agent disconnect, viewer-side hold (`held_for_viewer`), claim fencing + rebuild/re-attach (`resume_claimed`, `confirm_resumed`, `refuse_claim`), controller `rejoin`, overdue `run_sweep`, and `resume_gate` re-authorization | `crates/modules/fleet/src/hub/resume.rs:268`, `:582`, `:685`, `:749`; `crates/modules/fleet/src/hub/hold.rs:60`; `crates/modules/remote/src/resume.rs:137`; `crates/modules/remote/src/rejoin.rs:214`; `crates/modules/remote/src/sweep.rs:94`; `crates/modules/remote/src/controller.rs:1455` |
| Agent (`meshharbord`) | `SessionTable` owned across reconnects, `rc_sessions_survive_reattach` (default ON, acts only under an announced window), 120 s `WINDOW_CAP`, 12 transient vs 4 terminal `ConnExit` arms, peer-to-peer `rc:ended`, and supervised Mac delegation (`DelegateHost` records + GUI worker `DelegatedSide` + `OrdersLane` + `WORKER_ENV_FORWARD`) | `agents/meshharbord/src/session_table.rs:75`, `:105`, `:618`, `:1281`, `:1518`; `agents/meshharbord/src/delegate.rs:330`, `:1495`; `agents/meshharbord/src/delegate_worker.rs:241`; `agents/meshharbord/src/macos_supervisor.rs:272` |
| Viewer (`ui`) | `createSessionHold`, `rc:session.rejoin`, `replaces` redial, `rc:ended` handling on the control DC, paint-gap measurement across `<video>` + all three decode workers (`rc-webcodecs-worker`, `rc-hevc-worker`, `rc-vp9-444-worker`), and `rc.resume` telemetry record | `ui/src/composables/rcSessionHold.ts:62`, `:167`, `:333`; `ui/src/composables/rcResumeRecord.ts:158`; `ui/src/workers/rc-paint-gap.ts:48`; `ui/src/composables/useRemoteControl.ts:5610`, `:5706` |

## MeshHarbor-specific invariants

- **FR-128 / FR-134 management path:** a device's control socket may reconnect directly or through
  a zone gateway; `kept_sessions` rides the same `rc:agent.hello` on any path.
- **FR-129 device 2FA & FR-127 protected device:** resume only continues a session the device
  already admitted; it never opens a new session without device 2FA or protected-device checks.
  `consent::strictest_of` keeps the device's own setting as the floor.
- **File child transports & zone routes:** a re-attached session keeps its file-child bookkeeping
  and zone route; a rebuilt session (after pod death) enforces the current zone route (never falling
  open to `ZoneRoute::Open` under a strict zone policy) and revokes file child transports
  fail-closed (`rc:file.child.revoke` right after `rc:session.resumed`).
- **Device shares:** a share-link session sets `external = true`, announces no `resume_secs`, and
  is never detached or held (either side's socket loss terminates it immediately).
- **Peer cleanup:** every WebRTC peer that really ends is explicitly `close()`d within
  `PEER_CLOSE_BUDGET` (dropping frees nothing).

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P1 | Server: resume wire, row fields, audit kinds, window setting + resume scope, the claim, the sweep | server window `0` (off) + empty `rc_resume_scope` | implemented & tested |
| P2 | Agent: keep sessions through a control-socket loss, claim them on reconnect, bounded by the window (incl. P2b Mac delegated sessions and P4-0/P4-1 window gating) | `rc_sessions_survive_reattach=off` + no announced window | implemented & tested |
| P3 | Viewer: hold a resumable session through the gap, rejoin it, measure paint gap across all decode paths | follows the server's `resume_secs` | implemented & tested |
| P4 | Field: Linux release, set `MESHHARBOR__RC__SESSION_RESUME_SECS=60` + stage `/api/admin/rc-resume-scope`, server restart during a live session | window `0` / empty scope | pending field test |

Windows and macOS agents stay on 0.4.200 until their builds return; a device without the verb keeps
today's behaviour (the server never announces a window to it).

## Acceptance criteria

- [ ] **AC1.** A live direct/TURN session survives a production API restart with no new session row
  and no new consent prompt (field, red on the current deploy first, then green).
- [x] **AC2.** A kick or revoke issued during the gap ends the session at the reconnect, never
  later than the window (automated tests: `rc_resume_lifecycle_tests`, `rc_resume_policy_tests`,
  `session_table::tests`).
- [x] **AC3.** A session nobody reclaims ends at the deadline and its peer is closed (automated
  tests: `rc_resume_sweep_tests`, `hub::hold::tests`, `session_table::tests`).
- [x] **AC4.** A device or server without the feature behaves exactly as before (automated tests:
  `rc_resume_compat_tests`, `session_table::tests::p4_0_*`).
- [x] **AC5 (docs).** The remote-control docs describe the detach/resume lifecycle (mermaid, anchors)
  and a row in [docs/README.md](../README.md).

## Out of scope

External (FR-52) and device-share sessions end as today (upstream D3). DERP sessions resume only if
their path returns before ICE gives up.

## Field-verification log

| When (UTC) | What | Result |
|---|---|---|
