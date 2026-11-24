# FR-130: The session outlives its control socket — a server restart no longer ends a remote-control session

> **Status:** in progress — claimed 2026-11-24. Tracking issue: none (GitHub Issues are disabled on
> this repository); this spec and its registry row are the record. A port of upstream roomler-ai's
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
- FR-128 puts a CN-zone device's control socket through its zone gateway; a gateway update or a
  cross-border wobble drops it the same way.

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P1 | Server: resume wire, row fields, audit kinds, window setting + resume scope, the claim, the sweep | server window `0` (off) | planned |
| P2 | Agent: keep sessions through a control-socket loss, claim them on reconnect, bounded by the window | device switch + no announced window | planned |
| P3 | Viewer: hold a resumable session through the gap and rejoin it | follows the server | planned |
| P4 | Field: Linux release, window on, a server restart during a live session | window `0` | planned |

Windows and macOS agents stay on 0.4.200 until their builds return; a device without the verb keeps
today's behaviour (the server never announces a window to it).

## Acceptance criteria

- [ ] **AC1.** A live direct/TURN session survives a production API restart with no new session row
  and no new consent prompt (field, red on the current deploy first, then green).
- [ ] **AC2.** A kick or revoke issued during the gap ends the session at the reconnect, never
  later than the window (tests).
- [ ] **AC3.** A session nobody reclaims ends at the deadline and its peer is closed (tests).
- [ ] **AC4.** A device or server without the feature behaves exactly as before (tests, mixed fleet).
- [ ] **AC5 (docs).** The remote-control docs describe the detach/resume lifecycle (mermaid, anchors)
  and a row in [docs/README.md](../README.md).

## Out of scope

External (share-link) sessions end as today (upstream D3). DERP sessions resume only if their path
returns before ICE gives up.

## Field-verification log

| When (UTC) | What | Result |
|---|---|---|
