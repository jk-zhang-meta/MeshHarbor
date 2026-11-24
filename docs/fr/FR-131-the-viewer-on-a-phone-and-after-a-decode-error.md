# FR-131: The viewer on a phone held sideways, and after a decode error

> **Status:** in progress — claimed 2026-11-24. Tracking issue: none (GitHub Issues are disabled on
> this repository); this spec and its registry row are the record. Ports of upstream roomler-ai's
> FR-125 (immersive landscape on phones, `8aa77f8d2`), FR-135 R1 (a decode error recovers in place,
> `b8c6d1b31`) and FR-120 P1b (a greyed viewer control says why, `dbfc603a2`).

## Goal

- **Sideways phone:** in a connected session on a coarse pointer in landscape, the bars step aside and
  the remote desktop gets the whole screen; one tap brings them back. The stage is never resized by
  showing or hiding the bars (a resize re-sends `rc:resolution`). Upstream measured 182–254 px of
  picture on common phones before.
- **Decode error:** the data-channel decoder is rebuilt in place and waits for a key frame (upstream:
  9.4–10.2 s → median 149–188 ms), with a budget of 3 rebuilds in 10 s before the old path takes over.
- **Greyed controls** say why, where a finger can read it.
- The viewer's remaining English strings get Chinese (the product speaks English and Chinese).

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P1 | Immersive landscape (FR-125 port) | the mode applies only on coarse pointer + landscape + connected | planned |
| P2 | Decode recovery in place (FR-135 R1 port) | a local switch (upstream `roomler-rc-decode-recover=0`, renamed to our prefix) restores the old path | planned |
| P3 | Greyed control reasons (FR-120 P1b) + the viewer's remaining strings in both languages | — | planned |

## Acceptance criteria

- [ ] **AC1.** On a 844×390 coarse-pointer viewport in a connected session the stage takes the full
  height; toggling the bars sends no `rc:resolution` (tests + headless field run).
- [ ] **AC2.** A forced decode error repaints within 500 ms on Chromium (field, Surface or MacBook as
  the host), red on the current deploy first.
- [ ] **AC3.** Phone portrait, tablets and desktops are unchanged (tests).
- [ ] **AC4.** No viewer string is English-only in the Chinese UI (i18n parity test).
- [ ] **AC5 (docs).** `docs/remote-control.md` / `docs/ui.md` describe both and a row in
  [docs/README.md](../README.md).

## Field-verification log

| When (UTC) | What | Result |
|---|---|---|
