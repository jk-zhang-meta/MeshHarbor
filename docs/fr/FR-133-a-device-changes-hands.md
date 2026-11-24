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

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P1 | Server: a device moved by a person-approved enrollment of the same machine into another org removes its old row (removal sequence, audit, admin notice) | server setting (off = 403 as today) | planned |
| P2 | Tray: detect the other-org sign-in, ask, move or keep | — | planned |
| P3 | `mh login --replace` uses the same removal | — | planned |

## Acceptance criteria

- [ ] **AC1.** Sign-in by a member of the device's org: no prompt, nothing changes (tests).
- [ ] **AC2.** Move: the device is in the new org, gone from the old org's list, the old org's audit has
  the entry and its admins the notice; the overlay lease is released by the normal sequence (tests,
  then field).
- [ ] **AC3.** Keep: identical to today (tests).
- [ ] **AC4.** A device cannot remove its old row without a person-approved enrollment of the same
  machine elsewhere; a plain `self/unenroll` of a permanent device is still 403 (tests).
- [ ] **AC5 (docs).** The enrollment/multi-org docs describe the move (mermaid, anchors) and a row in
  [docs/README.md](../README.md).

## Out of scope

Temporary (invitation) devices keep `mh leave`. Secondary org enrollments stay as they are.

## Field-verification log

| When (UTC) | What | Result |
|---|---|---|
