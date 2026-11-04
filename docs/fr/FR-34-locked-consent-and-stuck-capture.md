# FR-34 — A locked host: consent you can't see, and a stream that comes up black

> **CLOSED 2026-08-30** — issue #917 is closed and its acceptance criteria are met. Any status line below is the state while the work was in flight, kept as the record.

**Issue:** [#917](https://github.com/gjovanov/roomler-ai/issues/917)
**Status:** design

## Goal

Controlling a **locked** Windows host must work: the operator at that host can
see and answer the consent prompt, and once they approve, the controller gets a
live screen — without having to refresh. Today neither holds on a perMachine /
SYSTEM host that is locked when the session starts.

## Root cause / field evidence

Field, 2026-08-29, `neo16` (controller) → **CORPLAP-1** (CORPLAP-1, Windows corp
laptop, perMachine SCM / SYSTEM, hybrid Intel Iris Xe, 0.4.17). The operator's
own account:

> it was locked and awaiting consent approval — on the lock screen the consent
> window isn't visible. I logged in directly on CORPLAP-1, saw the consent
> window, approved, and it disappeared — but on neo16's browser it was a black
> screen. Only after refreshing neo16's page did CORPLAP-1's screen come back.

Two independent defects, plus the trigger that chains them.

### 1. The consent panel is invisible on the lock screen — `indicator/win.rs`

The FR-27 native consent panel (`RoomlerConsentWClass`) is a window on the
**interactive** desktop. When the machine is locked, the input desktop is the
secure `Winlogon` desktop, where an ordinary window cannot appear — so a locked
host cannot show the prompt at all. The operator had to unlock first, which is
what set up defect 2. (The M3 lock-screen work put the video *capture* on the
secure desktop; this newer window is not there.)

### 2. A DXGI duplication bound during the lock→unlock transition returns empty frames forever — `system_context/capture_pump.rs:570`

The black session's own log (session `6a930b60`) is unambiguous:

```
16:40:16.5  PC state change … Connected;  all data channels opened
16:40:16.5  input: SystemContext worker — Locked-state suppression disabled (remote unlock enabled)
16:40:17.8  DXGI-direct: bound Desktop Duplication to the primary-output adapter (Intel Iris Xe)
16:40:17.8  capture: backend=system-context (DXGI + GDI fallback) 1920x1200
…            (13 s of:)
16:40:30.9  capture produced no frame (idle screen)  frames_empty=200000+  frames_unchanged=0
16:40:31.3  session terminated by server  reason=ControllerHangup
```

`frames_empty` (the duplication delivered **nothing**) climbed past 200 000
while `frames_unchanged` (we have a frame identical to the last — the real
idle-screen case) stayed **0**. The duplication was bound at 16:40:17.8, the
instant the desktop switched secure→default on unlock, and then
`AcquireNextFrame` returned `DXGI_ERROR_WAIT_TIMEOUT` for the rest of the
session — bound to a desktop/output that would never change.

The pump handles the two *error* transitions — `AccessLost` → `reset()`,
`DesktopMismatch` → `try_change_desktop()` — but `WAIT_TIMEOUT` maps to
`BackendBail::Transient`, whose arm is:

```rust
Err(BackendBail::Transient) => {
    *consecutive_hard = 0;
    *consecutive_access_lost = 0;
    *consecutive_empty = consecutive_empty.saturating_add(1);
    Ok(None)                       // ← no recovery, ever
}
```

The routing doc even reads `Transient → Ok(None) — no frame this tick (idle-
keepalive will fire upstream)`, i.e. it assumes Transient means "idle screen,
nothing changed." That is true for a *working* session that goes idle; it is
false for a duplication that came up stuck and has **never delivered a frame**.
The two are trivially separable: a stuck duplication has `frames_delivered == 0`
for its whole life.

Only a fresh session recovered it — session `6a930b80`, created 1 s after the
hangup, rebuilt the duplication on the now-settled desktop and ran at 18 fps
(HEVC). A reconnect should not be the only recovery.

### 3. The idle/empty optimisation must never suppress the FIRST frame

Compounding 2: even a genuinely idle screen must send an initial (key)frame, or
the controller is black until something moves. The output-suppression on
"unchanged/empty" is only sound *after* one frame has reached the controller.

## Key design

| # | Phase | Fix | Kill switch |
|---|---|---|---|
| 1 | **Stuck-duplication recovery** | In `capture_pump`, track `frames_delivered` (reset on every backend (re)build). When `frames_delivered == 0` and `consecutive_empty` crosses `STUCK_EMPTY_THRESHOLD`, `try_change_desktop()` + rebuild DXGI; if a second streak follows the rebuild, fall to the always-delivers GDI BitBlt path (as the `AccessLost` arm already does at its threshold). **Gated on `frames_delivered == 0`, so a session that has ever shown a frame is byte-for-byte unaffected** — the worst case for the change is a came-up-black session that stays black, i.e. no regression over today. | env `MESHHARBORD_STUCK_CAPTURE_RECOVERY=0` |
| 2 | **First-frame guarantee** | P1 already prevents a *permanent* black on a static screen (its GDI backstop delivers a frame) but only after the 2 s stuck window. P2 shortens the wait: when DXGI has delivered no frame within `FIRST_FRAME_GDI_AFTER` (300 ms), the SystemContext worker primes **one** GDI BitBlt frame (always the current screen) so the controller sees the desktop ~instantly on connect — **without** swapping the backend or setting `delivered_since_build` (DXGI takes over at full quality the moment it delivers, and a truly-stuck DXGI is still caught by the 2 s `capture_is_stuck` path). One-shot per session. | `MESHHARBORD_STUCK_CAPTURE_RECOVERY=0` (shared with P1) |
| 3 | **Tell the controller the host is locked** | Unlock-then-approve is the SOUND flow — you unlock (proving you are at the machine), then approve — and with P1+P4 it works. The gap is that the controller has no way to know it is locked, so its "awaiting consent" wait looks like a hang. The agent probes lock state at prompt time and, if locked, sends `rc:consent.pending{host_locked}` over the WS; the hub relays it; the viewer turns the wait into an instruction ("unlock the device and approve, 5-min window"). | advisory + additive; absent = generic wait |
| 4 | **A 5-minute attended window** | Plain `prompt` gave the operator 30 s — not enough to reach a LOCKED machine, unlock, and approve. Extend `DEFAULT_CONSENT_TIMEOUT` to 5 min (`prompt_then_email`'s host half stays 30 s — its emailed link is the fallback), and show the countdown as `m:ss`. | — |
| 3b | **Detect the lock from the SERVICE context** | P3 shipped in 0.4.22 but the emit **could never fire on a perMachine/SYSTEM host**: the consent code runs on the SCM service window station (the daemon switches to `WinSta0` per-session, *after* consent), so the `OpenInputDesktop`-based `probe_lock_state()` read the service station's own `Default` → Unlocked, always. Fix = `probe_lock_state_service()` via `WTSQuerySessionInformationW(WTSSessionInfoEx).SessionFlags` (window-station-independent), used at the emit with a fallback to the desktop probe. Field-confirmed on CORPLAP-1, 0.4.22; fix ships in 0.4.23. | advisory; WTS UNKNOWN/failure → desktop-probe fallback → generic wait |

Phase 1 is the functional fix (black → live without a refresh) and is safe to
ship on its own by the `frames_delivered == 0` gate.

⚠️ **Rejected: rendering the consent panel on the secure desktop.** The original
P3 was to draw the FR-27 panel on the `Winlogon` desktop so a locked host could
be answered WITHOUT unlocking. Dropped after the field test resolved the design
question: the operator confirmed unlock-then-approve is fine ("can't we allow the
user to do a sys unlock and then show the consent prompt — or is this a design
flaw?"), and it is not a flaw — unlocking proves physical presence, which is
exactly what a consent gate wants. On top of that the secure-desktop approach is
high-risk and un-verifiable remotely: modern Win11 heavily restricts third-party
windows on the locked secure desktop, the panel is `WDA_EXCLUDEFROMCAPTURE` so it
can never be observed even through an RC session streaming the lock screen, and
the daemon cannot lock its own controlling host to test. So P3 became the much
smaller, fully-verifiable "tell the controller it is locked" above.

## Acceptance criteria

- [x] A duplication that comes up delivering no frames recovers **in-session**
      (rebind → GDI backstop), so the controller gets a live screen without a
      reconnect. **Field-verified on CORPLAP-1, 2026-08-29** (P1, #919): locked →
      session → unlock+approve → neo16 got the screen live, no refresh.
- [ ] A session that has ever delivered a frame is unaffected (no extra
      rebuilds, idle optimisation intact).
- [x] Connecting to a genuinely static screen shows an initial frame, not black.
      Met by P1 (GDI backstop delivers within ~2 s — never permanent black) and
      tightened by **P2** (one-shot GDI first frame within ~300 ms of connect).
      ⏳ field-verify P2's timing on a truly static screen on the next release.
- [ ] The controller is TOLD the host is locked while a consent prompt is
      pending, so its wait reads as "unlock the device and approve" rather than
      a hang (phase 3). ⚠️ Rendering the panel on the secure desktop is
      REJECTED (see above) — unlocking to approve is the intended flow.
- [x] Field-verified on **CORPLAP-1** (2026-08-29): lock → session → unlock →
      approve → the screen comes up live, **no refresh** (the black-until-refresh
      is fixed). The prompt is still not visible *while* locked — that is P3.
- [ ] The attended `prompt` window is long enough to reach a locked machine
      (P4, 5 min).

## Out of scope

- The lock→unlock capture behaviour on GDI-only / non-SystemContext hosts (they
  BitBlt the current screen every frame and don't exhibit this).
- FR-22 time-to-first-frame (a different, non-locked path).

## Field-verification log

### 2026-08-29 — P1 on CORPLAP-1 (operator's own repro)

> lock → session (I don't see the approve window while in lock, had to unlock on
> CORPLAP-1 itself) → I unlocked → approved and neo16 got the screen. However while
> locked still no consent window. Also 30 s timeout is too short — set it to 5 min.

- **P1 (stuck-capture recovery): PASS.** After unlock+approve the controller got
  a live screen with **no refresh** — the black-until-refresh from the original
  report is gone. (Contrast: the incident session sat black for 13 s and only a
  reconnect recovered it.)
- **P3 reframed.** The operator asked "can't we unlock then show the prompt — or
  is this a design flaw?" It is NOT a flaw: unlock-then-approve is the sound flow
  (unlocking proves presence). So rendering on the secure desktop was rejected;
  P3 became "tell the controller the host is locked" so its wait reads as an
  instruction instead of a hang.
- **P4 (window length):** 30 s was too short to walk to a locked machine — raised
  to 5 min.

### 2026-08-30 — P3 shipped in 0.4.22, field-tested on CORPLAP-1: the emit was broken

Rolled 0.4.22 (agent) + deployed the API/UI, updated CORPLAP-1, staged
`consent_mode=prompt` + `prompt_owner=true`, and drove sessions from neo16 with the
operator holding the host on the lock screen.

- **Unlocked path: PASS** — the agent correctly does NOT claim locked; the viewer
  shows the generic *"Waiting for the agent to allow the connection…"*.
- **`prompt_owner`: PASS** — the owner session held in `awaiting_consent` (did not
  owner-auto-grant) and connected only after approval at the device.
- **Locked path: FAIL — real bug.** With the host genuinely locked (operator held
  it; zero interfering sessions confirmed via `pump_heartbeats=0`), every attempt
  still showed the generic message. The agent log confirmed the emit path ran
  (`consent prompt surface`) but produced **no** `consent prompt on a LOCKED host`
  line — `probe_lock_state()` returned **Unlocked while locked**.
  - **Root cause (code-confirmed).** `probe_lock_state()` classifies via
    `OpenInputDesktop`, whose result is the input desktop of the **calling
    process's window station**. The consent code runs on the SCM **service**
    window station (`Service-0x0-…`); the daemon only switches to the interactive
    `WinSta0` per-session via `attach_to_winsta0()`, when input is wired, **after
    consent** (`input/system_context_backend.rs`, `capture_pump` worker). The
    service station has its own `Default` desktop → `classify(true,"Default")` →
    Unlocked, always. On a perMachine/SYSTEM host the emit was **structurally
    unable to fire**. (The daemon's `spawn_monitor`, which polls *after* the
    switch, cleanly logged `transition → Winlogon/Locked`, which is what exposed
    the asymmetry.)
  - ⚠️ **CI was green** — the unit tests exercise `classify()`'s desktop-name
    logic, not the window-station context the emit runs in. The **field test is
    what caught it** (CI green ≠ done).
  - ⚠️ CORPLAP-1 has **Windows Hello**: it re-unlocked within ~1 s of each Win+L
    while the operator faced it, which masked the diagnosis for several rounds
    until the lock was held with the camera covered.

### P3b — detect the lock from the service context (the fix)

`lock_state::probe_lock_state_service()`: read the console session's lock via
`WTSQuerySessionInformationW(WTSSessionInfoEx).SessionFlags`, which is
window-station-independent (the documented way to read lock state from a session-0
service). The emit uses it and falls back to `probe_lock_state()` (still correct
for a perUser/attended daemon already on `WinSta0`) on WTS unavailable/UNKNOWN.
Pure `classify_session_flags()` + unit test; Win7/2008R2 flag-inversion caveat
documented (fleet is Win10/11). Ships in 0.4.23; re-verify on CORPLAP-1 held locked.
