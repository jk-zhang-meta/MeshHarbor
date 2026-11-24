# FR-131: The viewer on a phone held sideways, and after a decode error

> **Status:** P1–P3 built on `feat/fr-131-viewer-phone-decode` (2026-11-24), local checks green; field
> verification owed (AC1's field half, AC2). Claimed 2026-11-24. Tracking issue: none (GitHub Issues are disabled on
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
| P1 | Immersive landscape (FR-125 port) | the mode applies only on coarse pointer + landscape + connected; per browser, Settings → Display → "Immersive when sideways on a phone" (`meshharbor-rc-immersive.v1=off`) | built, tests green; field owed |
| P2 | Decode recovery in place (FR-135 R1 port) | `localStorage.setItem('meshharbor-rc-decode-recover', '0')`, then reconnect: the old path | built, tests green; field owed |
| P3 | Greyed control reasons (FR-120 P1b) + the viewer's remaining strings in both languages | — (strings only) | built, tests green |

## Design (on our code)

### P1 — immersive landscape (upstream FR-125, `8aa77f8d2`)

- **The predicate.** `isPhoneSideways(coarse, w, h)` = coarse pointer, wider than tall, under 500 px
  tall ([`useImmersiveViewer.ts:31`](../../ui/src/composables/useImmersiveViewer.ts#L31)); the viewer's
  `immersive` adds a connected session and the setting
  ([`RemoteControl.vue:2729`](../../ui/src/views/remote/RemoteControl.vue#L2729)).
- **The shell.** The viewer sets one flag (`setImmersiveViewer`) and clears it on unmount; the app bar
  binds it ([`AppLayout.vue:446`](../../ui/src/components/layout/AppLayout.vue#L446)). Our ws banners sit
  inside `<v-main>` (flat theme) and are not touched: a banner that appears still takes its row.
- **The toolbar.** In the mode it is `position: absolute` above the stage, `visibility: hidden` and
  translated out of view; revealed, only `transform` and `visibility` change
  ([`RemoteControl.vue:5785`](../../ui/src/views/remote/RemoteControl.vue#L5785),
  [`:5801`](../../ui/src/views/remote/RemoteControl.vue#L5801)). So the stage's box never changes when the
  bars show or hide, and the Fit / Match `ResizeObserver` has nothing to re-send.
- **The pull-tab** (48 × 36 px hit area, [`RemoteControl.vue:934`](../../ui/src/views/remote/RemoteControl.vue#L934))
  reveals it; 4 s without a touch inside it, or a tap on the stage, hides it again; an open Vuetify
  overlay (Settings, a menu) keeps it up (`armChromeHide`, [`:2747`](../../ui/src/views/remote/RemoteControl.vue#L2747)).
- **Fullscreen chip** once per browser where `document.fullscreenEnabled`
  ([`:943`](../../ui/src/views/remote/RemoteControl.vue#L943)); **touch presets fit** a short stage
  (`fitControls`, [`touchControls.ts:291`](../../ui/src/composables/touchControls.ts#L291)).
- **Differs from upstream:** our viewer has one toolbar row and no FR-116 P5c tools strip, so only the
  toolbar becomes the overlay (upstream's strip offset `--rc-tb-h` is gone); storage keys
  `meshharbor-rc-immersive.v1` / `meshharbor-rc-fullscreen-chip.v1`; the pull-tab takes the flat theme's
  hairline and `--mh-overlay-shadow`.

### P2 — a decode error recovers in place (upstream FR-135 R1, `b8c6d1b31`)

- **The decision** — before the first frame: no (ban the transport, renegotiate, as before); switch off:
  no; past 3 rebuilds in 10 s: no; otherwise rebuild (`createDecodeRecovery`,
  [`rc-decode-recovery.ts:77`](../../ui/src/workers/rc-decode-recovery.ts#L77)).
- **The rebuild** closes the dead decoder, builds a new one, asks for a key frame at once; the gate drops
  deltas meanwhile (`rebuildDecoder` / `onDecoderFailure`,
  [`rc-vp9-444-worker.ts:481`](../../ui/src/workers/rc-vp9-444-worker.ts#L481) /
  [`:506`](../../ui/src/workers/rc-vp9-444-worker.ts#L506),
  [`rc-hevc-worker.ts:497`](../../ui/src/workers/rc-hevc-worker.ts#L497) /
  [`:522`](../../ui/src/workers/rc-hevc-worker.ts#L522)).
- **A chunk gap** on the ordered channel re-arms the gate ([`rc-vp9-444-worker.ts:460`](../../ui/src/workers/rc-vp9-444-worker.ts#L460)).
- **The watchdog** counts only a decoding DC path's frames once it has one (`mediaAdvanced`,
  [`useRemoteControl.ts:733`](../../ui/src/composables/useRemoteControl.ts#L733)).
- **The switch** `meshharbor-rc-decode-recover=0` (`storedDecodeRecover`,
  [`useRemoteControl.ts:4885`](../../ui/src/composables/useRemoteControl.ts#L4885)), read once per connect
  ([`:11571`](../../ui/src/composables/useRemoteControl.ts#L11571)).
- **Differs from upstream:** no FR-130 colour-space retry here, so `rebuildDecoder` is new rather than a
  rename, and clears our `pendingDecodeAt` map; upstream's `rc:decode-error` report to the agent does not
  exist here and is not ported; our chunk-framing receiver flags a gap on an eviction but not on an
  overtaken frame (upstream fixed that later, `8f5ea492e`, unordered-only, not ported), so the worker
  tests drive the eviction path. The lab e2e spec is not ported. Full write-up:
  [remote-control.md §11.10](../remote-control.md#1110-a-decode-error-recovers-in-place-fr-131-p2).

### P3 — greyed controls say why; the viewer in both languages (upstream FR-120 P1b, `dbfc603a2`)

- P1b applied cleanly: captions under disabled Settings toggles, tap-to-explain spans on refused toolbar
  controls (`explainRefusal`, [`RemoteControl.vue:2696`](../../ui/src/views/remote/RemoteControl.vue#L2696)),
  the touch-mode tap says how the mode works, a failed transfer's error as text, named icon buttons, and
  Vault's Approve.
- Every remaining viewer string in `remote.viewer.*` / `keepBusy.*` (en + zh-CN): the template and script of
  `RemoteControl.vue`, `components/remote/*` (RdpFallbackCard was Chinese-only and gained English), and the
  helpers whose sentences the viewer shows. `useRemoteControl`'s session machinery is untouched (FR-130 is
  in flight there): its own constants and literals are translated where shown, by `rcSays`
  ([`rcSays.ts:74`](../../ui/src/composables/rcSays.ts#L74)), with a drift test. Low-level transfer/channel
  diagnostics inside "Upload failed: …" stay as written; the server's and the device's words show as sent.

## Acceptance criteria

- [ ] **AC1.** On a 844×390 coarse-pointer viewport in a connected session the stage takes the full
  height; toggling the bars sends no `rc:resolution` (tests + headless field run).
  - [x] Test half: `useImmersiveViewer.spec.ts` — 844×390 with a finger is immersive, and in the mode the
    toolbar is absolutely placed and its revealed state changes only `transform`/`visibility` (no box the
    stage could see), with no `v-if`/`v-show` on the bar.
  - [ ] Field half: a live session on a phone held sideways (owed).
- [ ] **AC2.** A forced decode error repaints within 500 ms on Chromium (field, Surface or MacBook as
  the host), red on the current deploy first.
- [x] **AC3.** Phone portrait, tablets and desktops are unchanged (tests): `isPhoneSideways` is false
  upright, for tablets either way, at the 500 px boundary and for a fine pointer
  (`useImmersiveViewer.spec.ts`), so none of them enters the mode; the full suite is otherwise unchanged.
- [x] **AC4.** No viewer string is English-only in the Chinese UI (i18n parity test):
  `remoteViewerI18n.spec.ts` (no English word in any viewer template — red against master's
  `KeepBusyMenu.vue`; every `remote.*` / `keepBusy.*` key has Chinese except 6 technical names) and the
  parity test `i18n.spec.ts`.
- [ ] **AC5 (docs).** `docs/remote-control.md` / `docs/ui.md` describe both and a row in
  [docs/README.md](../README.md).

## What the field test must check

1. **A phone held sideways, live session** (AC1's field half): connect from a phone (or a coarse-pointer
   emulation at 844×390), hold it sideways; the app bar and toolbar leave and the picture fills the page.
   Tap the pull-tab, wait 4 s, tap the stage: the console must show **no** new `rc:resolution` /
   `[rc] fit` line for the reveal and the hide (one is expected on entering the mode itself). Turn the
   setting off in Settings → Display: the bars stay. Upright: normal layout.
2. **A forced decode error** (AC2): upstream forced one from outside the product — its Playwright spec
   routed the page's `rc-vp9-444` / `rc-hevc` worker script through a shim that wraps `VideoDecoder` and,
   on cue, feeds the running decoder a random 2 KB chunk marked as a key frame; Chromium answers
   `Decoding error.` (its FR-132 AC3 method). Measure error → next paint. Red first: on the current
   deploy, or with `meshharbor-rc-decode-recover=0`, the picture freezes ~10 s until the watchdog
   re-creates the session. Green: `[rc] vp9-444 decode recovered in N ms` with N ≤ 500 ms on Chromium.

## Field-verification log

| When (UTC) | What | Result |
|---|---|---|
