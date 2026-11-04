// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! M3 A1 — SYSTEM-context capture + input on the secure desktop.
//!
//! Mounted only when the `system-context` Cargo feature is enabled, and
//! every submodule is additionally `#[cfg(target_os = "windows")]` so
//! the surface compiles green on non-Windows targets when the feature
//! is selected (the underlying Win32 FFI is Windows-only by
//! construction).
//!
//! ## What this is
//!
//! M2 (Effort 2) ships a Windows Service that supervises a per-session
//! user-context worker via `WTSQueryUserToken` + `CreateProcessAsUserW`.
//! That covers the normal "user logged in to Default desktop" case. M3
//! Z-path (shipped 0.2.5) covers the lock-screen case by overlay-
//! freezing the captured frame and dropping input — a dignified pause,
//! but the operator can't *do* anything during it.
//!
//! M3 A1 closes the gap. When the active session is on the lock screen
//! (Winlogon desktop) AND a controller is mid-session, the SCM
//! supervisor spawns a parallel worker that runs as `S-1-5-18`
//! (LocalSystem) but in the active *interactive* session (so screen
//! injection lands on the right user's input device). Capture switches
//! from WGC (which fails session-0 activation per the 0.2.5 NO-GO) to
//! DXGI Desktop Duplication, which has no WinRT activation and works
//! cleanly under SYSTEM. Input is plain `enigo` `SendInput` from a
//! single dedicated thread that owns the `SetThreadDesktop` binding.
//!
//! ## Architecture summary (full plan in
//! `~/.claude/plans/floating-splashing-nebula.md`)
//!
//! 1. **`worker_role`** — startup probe. The agent binary launches
//!    every worker as itself (no CLI mode flag); each worker probes its
//!    own token via `GetTokenInformation(TokenUser)` and selects
//!    User-mode or SystemContext-mode plumbing. **THIS IS WHAT'S
//!    IMPLEMENTED IN THIS COMMIT.** Subsequent submodules follow.
//! 2. `winlogon_token` (TODO) — `OpenProcessToken(winlogon.exe)` +
//!    `DuplicateTokenEx(TokenPrimary)` + `SetTokenInformation(SessionId)`
//!    + `CreateProcessAsUserW` to spawn S-1-5-18 in session N.
//! 3. `desktop_rebind` (TODO) — `SetThreadDesktop(OpenInputDesktop())`
//!    on the dedicated input thread, with bail-on-change reporting
//!    upstream so the supervisor can swap workers if the desktop
//!    flip is permanent (logoff vs lock).
//! 4. `dxgi_dup` (TODO) — DXGI Desktop Duplication backend with
//!    granular `BackendBail` discrimination (5 variants per
//!    pre-flight #1).
//! 5. `gdi_backend` (TODO) — `BitBlt`-from-desktop-DC fallback after
//!    3 consecutive DXGI failures.
//!
//! ## Empirical validation
//!
//! All architectural assumptions verified on the field-test host via the M3 A1
//! pre-flight probe binary (`roomlerd system-context-probe ...`);
//! results saved to `project_m3_a1_preflights_2_3_5.md`. Bare token-dup
//! works on Win11 24H2 (no `AdjustTokenPrivileges` needed); SE_TCB and
//! SE_IMPERSONATE present in the spawned child by default; DXGI cadence
//! ~31% Ok / 69% WouldBlock under nominal user motion / 0% across all
//! error variants.

#![cfg(all(feature = "system-context", target_os = "windows"))]

pub mod capture_pump;
pub mod desktop_rebind;
pub mod dxgi_dup;
// rc.108 Phase 1 — adapter-bound DXGI Desktop Duplication that binds to the
// adapter owning the PRIMARY OUTPUT (the iGPU on a hybrid Optimus host), so
// capture stays on fast DXGI instead of falling to GDI BitBlt. Needs both
// the `windows` crate (`mf-encoder`) and the scrap fallback / DxgiFrame
// surface (`scrap-capture`) — i.e. the production `full-hw,system-context`
// MSI. See the module header for the WINHOST-B motivation.
#[cfg(all(feature = "mf-encoder", feature = "scrap-capture"))]
pub mod dxgi_direct;
// rc.105 Phase 0 — DXGI adapter/output enumeration for the hybrid-GPU
// capture diagnostics. Uses the `windows` crate, gated on `mf-encoder`
// (present in the production `full-hw` build).
#[cfg(feature = "mf-encoder")]
pub mod dxgi_util;
pub mod gdi_backend;
pub mod peer_presence;
pub mod user_profile;
pub mod winlogon_token;
pub mod worker_role;
