# FR-132: Phone parity, the rest — lists, dialogs and tables that fit a phone, in both languages

> **Status:** in progress — claimed 2026-11-24. Tracking issue: none (GitHub Issues are disabled on
> this repository); this spec and its registry row are the record. Ports of upstream roomler-ai's
> FR-120 P1a (`055432406`), P3 (`1cbb8e8a2`), P5 (`10abda8d8`), P4a (`11ee2a9a3`) and P4b
> (`41dc07dcd`). P2 and P6 were ported on 2026-11-23 (`7356bf4a1`, `36157b5e6`).

## Goal

The management pages fit a phone: what a chip or chart means is a tap away (P1a); dialogs and title
rows fit (P3); the tutorial scrolls inside the app and public pages never scroll sideways (P5);
Devices, the audits and Billing stay within about twice their desktop height (P4a); Members, Invites
and Files are one line a row (P4b). Upstream's strings are English literals; here every string goes
through the locale files in English and Chinese, and the flat theme's look (presence dot, row edge,
segmented control) is kept.

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P1 | P1a, P3, P5 | — (layout only) | planned |
| P2 | P4a, P4b, reimplemented on our components and i18n | — (layout only) | planned |

## Acceptance criteria

- [ ] **AC1.** At 390 px wide no management page scrolls sideways, and Devices/Members/Invites/Files
  rows read as upstream designed (headless shots, both languages).
- [ ] **AC2.** Desktop layouts are unchanged (tests).
- [ ] **AC3.** Every new string exists in en and zh-CN (i18n parity test).
- [ ] **AC4 (docs).** `docs/ui.md` describes the phone rules and a row in [docs/README.md](../README.md).

## Field-verification log

| When (UTC) | What | Result |
|---|---|---|
