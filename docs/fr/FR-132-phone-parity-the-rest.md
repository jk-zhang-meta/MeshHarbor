# FR-132: Phone parity, the rest — lists, dialogs and tables that fit a phone, in both languages

> **Status:** implemented on branch `feat/fr-132-phone-parity` (unmerged) — claimed 2026-11-24. Tracking issue: none (GitHub Issues are disabled on
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

## Key design

Anchors are in [docs/ui.md](../ui.md#phone-parity-the-rest-fr-132). Each upstream commit was applied with
`git apply -3` and the conflicts reimplemented on our code.

- **P1a.** `FactChip.vue:14` (new `plain` prop for the flat theme's presence word, which is a span, not a
  chip); `AgentsSection.vue` chips; `UptimeStrip.vue:198`, `UsageTimeline.vue:259`, `MeshGraph.vue`.
  Zone, relay and Device-configuration chips keep `v-chip` because their tap acts.
- **P3.** Dialog title rows in `AgentsSection.vue`, `MembersSection.vue`, `RolesSection.vue`,
  `OverlaySubnetRoutesSection.vue`, `GiphyPicker.vue`; titles reuse existing keys.
- **P5.** `TutorialView.vue:318`; `page-no-sideways` at `responsive.css:169`, applied to `AuthShell.vue:10`
  (our sign-in/sign-up frame replaced upstream's `v-container`); Growth and Observability tables stack.
- **P4a.** `useOpenRows.ts:15`; Devices cards (`AgentsSection.vue:622`) keep `.mh-presence`, `mh-row--*`,
  `osName()`; `EnrollKeysSection.vue:260`, `ExecAuditSection.vue:61`, `SshAuditSection.vue:70`,
  `BillingView.vue:155`.
- **P4b.** `MembersSection.vue:98`, `InviteManageView.vue:87`, `FilesBrowser.vue:79`, `RoomList.vue:127`,
  `AgentLogsDialog.vue:213`; usage and keep-busy-history tables stack as cards.
- **Skipped (viewer-owned):** `views/remote/RemoteControl.vue` (P3's agent-log dialog, with two of the
  ported spec's cases) and `components/remote/KeepBusyMenu.vue` (P5's `min()` width).

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P1a | what a chip or chart means is a tap away | — (layout only) | done (`7b0431935`) |
| P3 | dialogs and title rows | — (layout only) | done (`406b1e7ea`), viewer dialog skipped |
| P5 | tutorial scroll, no sideways scroll, operator tables | — (layout only) | done (`0ab5545a0`), KeepBusyMenu skipped |
| P4a | Devices, audits, Billing within 2x desktop height | — (layout only) | done (`5b9a1224a`) |
| P4b | Members, Invites, Files one line a row | — (layout only) | done (`67a6f603e`) |

## Acceptance criteria

- [x] **AC1.** At 390 px wide no management page scrolls sideways, and Devices/Members/Invites/Files
  rows read as upstream designed (headless shots, both languages: no document or `v-main` scroll width above 390 px on Devices, Members, Invites, Files, the command audit and the tutorial; the tutorial's `v-main` is `overflow-x: hidden` and can be nudged 4 px by script only).
- [x] **AC2.** Desktop layouts are unchanged (tests; 1440 px shots show the same tables, no phone rows).
- [x] **AC3.** Every new string exists in en and zh-CN (i18n parity test).
- [x] **AC4 (docs).** `docs/ui.md` describes the phone rules and a row in [docs/README.md](../README.md).

## Field-verification log

| When (UTC) | What | Result |
|---|---|---|
| 2026-11-24 | local only: `vue-tsc` 0 errors; `vitest run src/` 177 files passed, 1 failed (known `DevicesGeoAndRelay.spec.ts`, also fails on base); headless 390x844 and 1440x900, zh-CN and en | pass; not field-verified on a device |
