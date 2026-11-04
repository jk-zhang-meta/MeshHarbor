# FR-36 — Wayland capture, and unattended access

**Issue:** [#929](https://github.com/gjovanov/roomler-ai/issues/929) · **Status:** **CLOSED 2026-08-30 — every functional criterion field-verified.** The browser renders a GNOME Wayland desktop, drives it, types into it, sees the greeter and a locked screen, and survives a reboot with nobody logged in. ⚠️ Two performance numbers did NOT meet their stated bar; see the acceptance list · **Owner:** agent / capture

## Goal

Capture a **Wayland** desktop, **unattended** — including while the session is
locked and at the login greeter. Today the agent cannot capture Wayland at all:
it produces a black or wallpaper-only stream. That is a growing share of Linux
hosts, and on Apple Silicon it is *every* accelerated desktop.

Secondary: it is the only remaining lever on the ~27 fps ceiling, after
[FR-29](FR-29-x11-damage-capture.md) measured the X11 path to its floor
(~20 ms/frame at 1080p, indifferent to how the framebuffer was drawn, and
partial readback ruled out because a window drag reports ONE full-screen damage
rectangle).

## ⚠️ P0 DECIDED — and it reverses this spec's first draft

The original plan was portal-first (`xdg-desktop-portal` ScreenCast → PipeWire),
with a session-resident broker to satisfy the portal's per-user-session
requirement and `persist_mode` restore tokens for unattended use.

**That plan cannot deliver unattended access.** RustDesk shipped the portal
path, hit the wall, and went around it. Their findings, which we should not
re-derive the expensive way:

- ScreenCast needs an **interactive consent dialog + monitor picker**, and the
  screencast exists only **inside an active user session**.
- `restore_token` only avoids re-prompting *after a human approved once* — it is
  not a headless grant.
- **While the session is LOCKED, mutter refuses to create or restore any portal
  screencast** (`Session creation inhibited`), and each locked attempt tends to
  **consume the saved restore token**, dropping back to the picker.
- Token behaviour is **inconsistent across compositors**; reboot/logout
  invalidates it, and other screencast apps (OBS) can interfere.

So the portal is structurally an *attended* API. A locked host — the normal
state of an unattended machine — is exactly where it refuses.

**Decision: capture below the compositor via DRM/KMS.** Read the scanout
framebuffer from the kernel, beneath both the compositor and its permission
prompt. This is compositor-independent (one backend for GNOME, KDE, XFCE, X11
and *no session at all*), works at the greeter, and dissolves the process-model
dilemma P0 was originally about — no session-resident broker is needed, because
we never talk to the session.

⚠️ The earlier recommendation (session broker + portal fd handoff over
`SCM_RIGHTS`) is **superseded**. It solved the wrong problem: it made the portal
reachable, when the portal is the thing that refuses.

## ✅ P1 go/no-go — MEASURED on `scw-m2-asahi`, 2026-08-29

The spec's stated first action was *"a linear-format grab that returns a sane
image, before any plumbing is written."* Done, with a ~120-line C probe
(`drmModeGetFB2` → `drmPrimeHandleToFD` → `mmap`). **It passes, and it resolves
the FR's largest risk.**

| question | answer |
|---|---|
| Does `apple-drm` scan out **tiled**? | **No — and it cannot.** The primary plane's `IN_FORMATS` blob advertises exactly **one** modifier: `DRM_FORMAT_MOD_LINEAR` |
| Live X11 (XFCE) grab | ✅ `fb 49, 1920×1080, XR24, modifier 0x0` — correct colours, geometry, text |
| Live **GNOME Wayland** grab | ✅ `fb 51, 4096×2160, **XR30**, modifier 0x0`, `allocated by = gnome-shell` |
| Is the grab **live** (not a stale buffer)? | ✅ opened a marked window, re-grabbed: **859,916 differing bytes**, new window present |
| Does it need DRM master? | **No.** Xorg (then mutter) held master throughout; `CAP_SYS_ADMIN` is what gates the GEM handle |
| Read cost, 1080p 8-bit (8.3 MB) | **1.58 ms** cached-map · 2.07 ms remapping every frame (5.2 GB/s) |
| Read cost, 4K 10-bit (35.4 MB) | **15.2 ms** cached-map · 16.7 ms remapping (2.3 GB/s) |

**Because the hardware plane accepts only LINEAR, no compositor on this platform
can hand it a tiled buffer.** That is a structural guarantee, not a lucky
sample — so **P2 (detiling) is not needed on Apple Silicon at all**. It stays in
the plan only for the tiled-scanout GPUs (Intel/AMD/Nvidia) that libdrmtap
exists to serve, and is no longer on the critical path for this host.

### ⚠️ Two findings that change the implementation

1. **GNOME scans out 10-bit `XR30` here, X11 scans out 8-bit `XR24`.** A backend
   written for `XRGB8888` alone produces a *structurally perfect, psychedelic*
   image — the probe did exactly that on its first Wayland run. P1 must branch on
   the fourcc: `XR30`/`AR30` unpack as one packed LE word `x:R:G:B 2:10:10:10`.
   The failure mode is silent and looks like a colour-space bug, not a format bug.
2. **The <10 ms bar is met at 1080p and MISSED at native 4K** (15.2 ms just to
   read, before any conversion or encode). Throughput also *halves* on the larger
   buffer (5.2 → 2.3 GB/s) — 35 MB does not stay in cache. So the fps half of
   this FR is resolution-dependent and must be reported that way, never as a
   single number.

## Prior art — read before building

- RustDesk blog: *Unattended Remote Access on Wayland* —
  <https://rustdesk.com/blog/unattended-remote-access-wayland/>
- Design discussion (the technical source):
  <https://github.com/rustdesk/rustdesk/discussions/15417>
- Restore-token failure modes:
  <https://github.com/rustdesk/rustdesk/discussions/10216>
- **`libdrmtap`** — <https://github.com/fxd0h/libdrmtap>

### ⚠️ Licensing — the distinction is load-bearing

- **`libdrmtap` is MIT** (C, with Rust bindings on crates.io). MIT is compatible
  with our MPL-2.0 agent side (FR-24).
- **RustDesk itself is AGPL-3.0.** Do **not** copy or adapt RustDesk source into
  this tree. Read their *discussion* for the design; take code only from the MIT
  library. FR-24's CI check asserts no AGPL crate reaches a shipped agent binary
  — a careless copy-paste is a licence violation, not merely a CI failure.

## Design

| Phase | What | Kill switch |
|---|---|---|
| **P1** ✅ | DRM/KMS capture as a fifth `ScreenCapture` backend (`capture/drm_backend.rs`): enumerate CRTCs, `drmModeGetFB2` the active scanout, PRIME-export, mmap, deliver `Frame`s. Handles **`XR24` + `XR30`** (both measured in the field). | **`MESHHARBORD_DRM_CAPTURE=1` to opt IN** — see below |
| **P2** | **Detiling** — EGL import + convert to linear. **NOT needed on Apple Silicon** (plane is LINEAR-only, measured); required for Intel `*_RC_CCS`, Nvidia block-linear. Deferred off the critical path. | same flag ⇒ fall back to portal/X11 |
| **P3** | **Privilege split.** A minimal helper holding `CAP_SYS_ADMIN`, passing **DMA-BUF fds over `SCM_RIGHTS`**; the daemon never needs the capability itself. | same flag |
| **P4** ✅ | Input on Wayland via **`uinput`** (`input/uinput_backend.rs`) — a virtual kernel device, so events enter through evdev beneath the display server. XTest reaches Xwayland clients ONLY, so without this a captured Wayland session is read-only. | **`MESHHARBORD_UINPUT=1` to opt IN** |

**Backend priority: DRM/KMS → portal/PipeWire → X11**, but DRM is **opt-in**
(`MESHHARBORD_DRM_CAPTURE=1`) rather than the Linux default — the inverse of this
repo's usual kill-switch shape, and deliberately so.

Measured on one host, one session, back to back at 1080p: scrap delivered **1 of
30** frames because FR-29's damage tracking proved the other 29 unchanged; DRM
delivered **30 of 30**, because DRM reports no damage and cannot know. Defaulting
it on would silently undo the FR-29 win (45.8 % → 2.8 % of a core, idle) on every
X11 host in the fleet. A Wayland or headless host opts in; everyone else keeps
the existing cascade byte-for-byte. The portal keeps its place as the *attended*
path (a logged-in user who consents once).

### Privilege model — do not simply run capture as root

`roomlerd` already runs as root, so P1 *can* open `/dev/dri/*` directly and P3
is tempting to skip. Do not skip it permanently. RustDesk's shape is a separate
`drmtap-helper` with `cap_sys_admin+ep`, `/dev/dri/`-only device access,
`PR_SET_NO_NEW_PRIVS`, a seccomp allowlist, and an 8-byte protocol whose only
attacker-controllable field is a CRTC-id equality filter. That is the right
target for a binary shipping to every fleet host — and it maps onto this repo's
existing self-spawn precedent (`roomlerd caps-probe`,
`#[command(hide = true)]` at `main.rs:149`, spawned via `current_exe()` at
`encode/caps.rs:79`), so it needs **no new packaged artifact**.

### The seam is unchanged

`ScreenCapture` (`capture/mod.rs:269`), chosen in `open_default`
(`capture/mod.rs:463`); backends at `:16` scrap, `:22` x11_damage, `:25` wgc,
`:34` synthetic. DRM is a fifth — no pump changes.

## Host readiness — measured on `scw-m2-asahi`, 2026-08-29

Every DRM prerequisite is already satisfied:

| requirement | state |
|---|---|
| **Active CRTC** (DRM capture needs live scanout) | `card2-HDMI-A-1 status=connected enabled=enabled`, mode 4096x2160 |
| Root / `CAP_SYS_ADMIN` | `roomlerd` runs as **root** |
| `/dev/uinput` for input | present; `CONFIG_INPUT_UINPUT=m` |
| `vkms` (virtual CRTC, if ever genuinely headless) | `CONFIG_DRM_VKMS=m` |
| Kernel ≥ 4.20 for `GETFB2` | **6.19.14-asahi** |
| GPU/EGL for detiling | works since the kernel upgrade (`glamor` on `Apple M2 Pro (G14S B1)`) |
| Wayland sessions installed | `gnome-wayland`, `gnome`, `gnome-classic-wayland`, `plasma` (+ mutter 48.8) |

⚠️ **DRM card numbering SHIFTED after the kernel upgrade** — the display
controller is now `card2` (it was `card0`), and `card1` is the `asahi` render
node. **Enumerate by driver/CRTC, never by a hard-coded card index.** The probe
selects the node whose `drmModeGetResources` reports `count_crtcs > 0 &&
count_connectors > 0`, which is the render-vs-display discriminator.

⚠️ **Screen blanking must stay off**, because DRM capture requires active
scanout — a blanked screen is not merely dark, it stops the thing we read.
[#921](https://github.com/gjovanov/roomler-ai/pull/921) already disables the X
server's built-in screen saver in VD mode for an unrelated reason; that is now a
*prerequisite*, and the DE-level screensaver/lock question it deliberately left
out of scope becomes in-scope here.

## Acceptance criteria

- [x] **A GNOME Wayland session on `scw-m2-asahi` yields real pixels.** Proven
      twice: by direct DRM probe, then through the shipped
      `capture::open_default` cascade. The **before** state is recorded beside
      it — the current path logs `scrap capture unavailable → NoopCapture (no
      primary display: connection refused)` and delivers **zero frames**
- [x] The P1 backend is **wired into the capture cascade** and delivers
      `Frame`s through the `ScreenCapture` trait (`roomlerd capture-smoke`)
- [x] **A browser-visible remote-control session against that Wayland desktop —
      PASSED 2026-08-30.** The viewer at `roomler.ai/.../remote` rendered the
      GNOME Wayland desktop of `scw-m2-asahi` (`connected`, H.264 SW, ~16 fps),
      and the daemon log names both backends for that session:
      `capture: backend=drm … node="/dev/dri/card2" 4096x2160` and
      `input: backend=uinput`. The gates came from **config, not env** —
      `config-backed env fallbacks registered keys=[…"DRM_CAPTURE"…"UINPUT"]` —
      which is the config-surface work paying off, because the daemon that
      served this session was spawned by the host's auto-start hook, outside
      systemd, where a unit env block would never have reached it.
      ⚠️ The viewer reported **2048×1080** for a 4096×2160 panel: the fused
      downscale is what fed the encoder. The X11 path would have shown
      1920×1080 — and on Wayland, nothing at all.
- [x] **Input, through the browser** — a click on the remote view opened
      **GNOME Shell's own calendar panel**, and `Escape` closed it again. So the
      pointer path and the physical-key (HID) path both reach a native Wayland
      compositor.
      ✅ **And you can now TYPE too (P4b, 2026-08-30).** The viewer sends
      composed text as `KeyText`, which the first cut dropped by design. It is
      now turned into physical keystrokes for a **detected, verified** layout:
      typing `echo FR36-TYPED-OK-123` in the browser put exactly that at the
      remote Wayland terminal prompt, and `Enter` ran it. Uppercase, digits and
      punctuation all survive, so the shift handling is right.
      ⚠️ Unknown layouts still refuse loudly, naming what was detected — see the
      open decisions for why this is a table and not `libxkbcommon`.
- [x] Streams **while the session is locked**, and **at the login greeter** —
      the cases the portal structurally refuses. Greeter: **20/20 frames with
      nobody logged in**. Locked: the XFCE unlock dialog captured.
      ⚠️ **A locked-and-IDLE screen is genuinely BLACK in scanout.** DRM
      reports it faithfully, but a viewer connecting to an idle locked host
      sees black until something wakes the display — do not diagnose that as a
      capture failure; it is FR-34 territory
- [x] **Survives a reboot with nobody logged in interactively — VERIFIED
      2026-08-30.** Cold boot with autologin disabled: `loginctl` showed only a
      `greeter` session for user `lightdm`, and the browser rendered **the login
      greeter** (`connected`, 26 fps, 1920×1080). The daemon was started at boot
      by its unit, and both config gates survived the reboot in
      `/etc/roomler/config.toml` — which is the point of them being config keys
      rather than env.
- [x] `avg_capture_ms` **< 10 ms** at **1080p** — measured **5.84 ms** for the
      whole backend (1.58 ms of that is the framebuffer read; the rest is the
      BGRA repack). Same host/session, scrap measured 5.11 ms
- [~] **4K: 43.8 ms undownscaled (still over the bar), but 24.0 ms via the
      production `Auto` path** after P1b fused the downscale into the repack —
      down from 52.9 ms, and faster than not downscaling at all
- [~] Sustained-motion fps **≥ 29** at `target_fps=30`. 1080p has headroom;
      4K through the production `Auto` path is now **~30 fps** (24.0 ms of a
      33 ms budget), up from ~19. Undownscaled 4K remains ~23 fps
- [x] Input reaches native Wayland clients (uinput), not only Xwayland ones —
      8 injected characters arrived in **GNOME Shell's own search box on
      Wayland**, read back off the scanout plane. Pointer verified objectively
      on X11: `0.25,0.75` → `480,809`, `0.8,0.2` → `1535,215`.
      ⚠️ `KeyText` and touch are **not** implemented (see open decisions)
- [x] X11/Windows/macOS unchanged — the backend is Linux-only, feature-gated,
      AND env-gated off; with the flag unset the same host still selects
      `backend=scrap` with X11 damage tracking active
- [x] Field-verified with the **before** state recorded beside the after


## Why this is closed with two criteria unmet

`avg_capture_ms < 10 ms` is met at 1080p (5.84 ms) and **not** at native 4K
(43.8 ms undownscaled). That number is not going to move much: 15.2 ms of it is
the framebuffer read itself, and the rest is a repack whose output is the same
size as its input, so the fusion trick that fixed the downscaled path has no
equivalent here. It is memory bandwidth on a unified-memory machine.

It is closed anyway because **the bar was the wrong proxy at 4K**. What the FR
actually needs is a usable session, and the production path — `Auto`, which
halves anything above 3.5 Mpx — delivers **24.0 ms, ~30 fps** at 4K. The
underlying goal is met; the intermediate metric is not, and it is recorded that
way rather than reworded into a pass.

Reopen this if a 4K Wayland session is measured behaving worse than that.

## Open decisions / risks

- ~~⚠️ **Asahi detiling is UNPROVEN — the single biggest technical unknown.**~~
  **RESOLVED 2026-08-29: no detiling needed.** The `apple-drm` primary plane's
  `IN_FORMATS` advertises `DRM_FORMAT_MOD_LINEAR` and nothing else, so a tiled
  scanout buffer is not representable on this hardware. Verified live under both
  Xorg and mutter.
- ✅ ~~**4K is the open problem, and it is memory bandwidth, not the loop.**~~
  **Largely fixed 2026-08-30 by fusing the downscale into the repack** —
  `Auto` at 4K went **52.9 ms → 24.0 ms**, which is *faster than not
  downscaling at all* (43.8 ms), because the write is 4× smaller while the read
  stays the same. ~30 fps at 4K instead of ~19.
  ⚠️⚠️ **The first attempt at this made it 6× WORSE (329.8 ms)** and the
  refutation is the useful part: the naive fusion sampled two source rows a
  whole pitch apart on every output pixel, and **the scanout mapping punishes
  strided access brutally**. Copying each row pair into cached scratch first —
  sequential reads, same arithmetic — is what won. **The cost model is
  sequential-vs-strided reads out of the mapping, NOT the number of passes over
  it**, which is also why the earlier "vectorise the loop" attempt changed
  nothing. Remaining at 4K undownscaled: 43.8 ms, still over the bar.
- Vendor `libdrmtap` (MIT, C + meson) vs reimplement the narrow slice in Rust.
  **The P1 probe is ~120 lines of libdrm calls with no detiling**, which shifts
  this decision toward reimplementing: vendoring adds a C build dep to every
  Linux agent build plus a drift-gate obligation, and its main value (detiling)
  is exactly the part Apple Silicon does not need. Re-open for tiled GPUs.
- ⚠️ **Which host can run the end-to-end browser test? Surveyed 2026-08-30:
  none of the fleet's Linux hosts can.**

  | host | DRM | connected outputs |
  |---|---|---|
  | `scw-m2-asahi` | `apple-drm` + `asahi` | **1** (`card2-HDMI-A-1`, 4096×2160) |
  | `jupiter` / `zeus` | `amdgpu` | **0** |
  | `mars` | no DRM device at all | — |

  So `scw-m2-asahi` is the *only* fleet machine with live scanout, and it is
  the one whose auto-start hook makes swapping the daemon impractical. Three
  ways forward, all operator calls: console access to that host to disable the
  hook; a new host with a real display; or `vkms` (a virtual CRTC — the module
  is present there, and it is the documented answer for a genuinely headless
  box) on a machine that is not a production cluster node.
- ⚠️ **P2 (detiling) is still OPEN for AMD/Intel/Nvidia — do not read the
  headless survey as retiring it.** `jupiter`'s `amdgpu` planes advertise
  `DRM_FORMAT_MOD_LINEAR` only, but that GPU has **nothing plugged in**, and a
  driver with no display to drive has no reason to offer a tiled scanout
  modifier. A desktop AMD card with an attached monitor is expected to expose
  `AMD_FMT_MOD` tiled formats. The Apple-Silicon result stands on its own
  because that plane *is* driving a 4K display; this one proves nothing.
- Multi-monitor: per-CRTC capture with physical origin/scale mapping.
- Cursor: the hardware cursor plane is captured separately; hotspot is
  approximate on bare metal. (Measured: `plane-1` sits unbound at `fb=0` while
  `plane-0` carries the desktop.)
- ⚠️⚠️ **The policy hazard is no longer hypothetical — it is demonstrated.** The
  greeter capture contains lightdm's **password field**, and the locked capture
  contains XFCE's **unlock dialog**. That is precisely the capability unattended
  access needs and precisely what must never be quietly enabled: gate it, audit
  it, and make the viewer indicator (FR-27) reachable on those surfaces before
  this leaves opt-in.
- Interaction with FR-27 (consent) and FR-34 (locked host): DRM capture makes
  the agent able to see a **locked** screen. That is the point for unattended
  access and simultaneously a policy question — it must be gated and audited,
  not quietly enabled.

- ⚠️ **`KeyText` is deliberately NOT implemented in the uinput backend.** evdev
  carries physical keys, so synthesising text needs the TARGET's keyboard
  layout — assuming US would type mojibake on every other layout. It drops
  loudly once per session rather than corrupting input quietly. A real fix
  reads the compositor's active layout (or uses the `xkbcommon` mapping) and is
  its own piece of work. Touch is likewise unimplemented (needs `ABS_MT_*`).
- ⚠️ **A uinput device is host-global.** It appears in every application's
  device list and injects into whatever has focus, including the greeter and
  the lock screen — the same policy weight as DRM capture, and the reason the
  gate is opt-in rather than a kill switch.

- ⚠️ **`KeyText` types only for layouts with a verified table (`us` today).**
  evdev carries physical keys, so "type z" means "press the key that produces z
  *under this host's layout*" — on a German layout that is the key labelled `y`.
  `libxkbcommon` is the correct general answer and was **rejected on deployment
  grounds**: it is a dynamic system library, and linking it would put
  `libxkbcommon.so` in `roomlerd`'s `DT_NEEDED` on every Linux build. Headless
  fleet hosts have no reason to carry it, and a missing `.so` does not degrade
  a feature — the loader refuses to start the daemon at all. That exact failure
  already cost this project once (vendored FFmpeg dylibs baking a Homebrew path
  into the macOS agent; dyld killed it at launch on every end-user Mac).
  So: detect the layout, type only where verified, refuse loudly otherwise.
  Adding a layout means adding a table and checking it — an unverified entry is
  worse than an absent one. ⚠️ There is deliberately **no operator override
  knob**: a new env would need a config-surface key to be settable the normal
  way and there is no string bridge yet, but more to the point, if detection is
  wrong the fix is to detect better, not to paper over it.

## Out of scope

- Replacing X11 or Windows/macOS capture. This adds a backend.
- The X11 fps ceiling itself — FR-29 measured it unreachable from that
  direction and is closed.

## Field-verification log

| date | build | result |
|---|---|---|
| 2026-08-29 | 0.4.20 (pre-FR baseline) | Wayland: **uncapturable**. X11 baseline same host: `avg_capture_ms` ~20 ms, ~27 fps at 1080p, idle 2.8 % of a core |
| 2026-08-29 | portal probe | `xdg-desktop-portal` reachable (4 portal names on the session bus) but **exposes neither `ScreenCast` nor `RemoteDesktop`** in an XFCE/**X11** session — those come from a compositor-matching backend. `-gnome` + `-gtk` installed; **`-kde` is NOT**. The agent must therefore *detect* ScreenCast, never assume it |
| 2026-08-29 | **P1 probe, X11 (XFCE)** | ✅ `card2`/`apple-drm`, `fb 49 1920×1080 XR24 modifier=0x0`. Correct image. Liveness confirmed (new window ⇒ 859,916 differing bytes). Read **1.58 ms** cached / 2.07 ms remap-per-frame |
| 2026-08-29 | **P1 probe, GNOME Wayland** | ✅ session switched to `gnome-wayland` (mutter 48.8). `fb 51 4096×2160 **XR30** modifier=0x0`, `allocated by = gnome-shell`. First decode was psychedelic — probe assumed 8-bit; with `XR30` unpacking the image is correct. Read **15.2 ms** cached (35.4 MB). Host reverted to XFCE; `roomlerd` PID unchanged across this switch pair |
| 2026-08-29 | **P1 backend, X11 (XFCE), 1080p** | ✅ `open_default` picks `backend=drm` under `MESHHARBORD_DRM_CAPTURE=1`; correct desktop image. **5.84 ms/frame, 30/30 delivered.** Same host, same session, scrap: **5.11 ms** but **1/30 delivered, 29 proven unchanged** — FR-29 damage tracking working, and the reason DRM must not be the default |
| 2026-08-29 | **P1 backend, GNOME Wayland, 4K** | ✅ **before:** the shipping path logs `scrap capture unavailable — falling back to NoopCapture (no primary display: connection refused)` — **zero frames**. **after:** `backend=drm`, **30/30 at 4096×2160 XR30**, correct image. ⚠️ **42.9 ms/frame raw, 52.9 ms with `Auto` downscale** ⇒ ~19 fps. Memory-bandwidth bound (~70 MB/frame). A vectorisable-loop rewrite was tried and **REFUTED** (43.8 vs 42.4 ms — no change) |
| 2026-08-29 | daemon impact | `roomlerd` restarted **once** during the whole session (`NRestarts=1`, 18:04), not coincident with either lightdm restart; ended `active/running`. The FR-19 relay it also hosts stayed reachable throughout (every measurement above arrived over its own control WS) |
| 2026-08-29 | **P1 at the LOGIN GREETER** | ✅ autologin disabled, lightdm restarted, **nobody logged in** (`loginctl`: only a `greeter` session for user `lightdm`). Shipping path: `NoopCapture`, zero frames. DRM: **20/20 at 1920×1080, 6.85 ms**, image is the lightdm greeter — user dropdown, password field, Log In button. This is the case the portal structurally refuses (no session ⇒ no portal) |
| 2026-08-29 | **P1 on a LOCKED session** | ✅ with a real locker running (`xfce4-screensaver`, `/lock/enabled=true`) DRM captured the **XFCE unlock dialog** — user `m1`, password field, Switch User / Cancel / Unlock. ⚠️ **The first attempt was a false negative twice over**, see below |
| 2026-08-29 | ⚠️ two false results caught | (1) `loginctl lock-session` reported success but `LockedHint` stayed `no` and no locker process existed — the screen was never locked, and the capture was an ordinary desktop. Claiming it would have been a **vacuous pass**. (2) With the locker genuinely active but idle, the capture was **pure black with every counter green** (15/15 frames, 6.71 ms). Waking the dialog with harmless input (mouse move + shift; no password typed) produced the lock screen — so the black was a **genuinely black screen**, faithfully reported |
| 2026-08-30 | **P4 uinput — pointer, objectively** | ✅ X11 session, `input-smoke --move-to`: `0.25,0.75` → pointer at **480,809**; `0.8,0.2` → **1535,215** (`xdotool getmouselocation`). Sub-pixel error is the 0..=32767 → 0..1919 scaling, not a mapping bug |
| 2026-08-30 | **P4 uinput — keyboard on WAYLAND, end to end** | ✅ 8 characters injected through `/dev/uinput` on GNOME Wayland arrived in **GNOME Shell's own search box** — the capture read back `terminal` in the search field with Xfce Terminal / Terminal / Konsole / XTerm as results. 21.4 M bytes differed between the before and after frames. Closed loop: **injected below the compositor, observed below the compositor** |
| 2026-08-30 | P4 hygiene | The virtual device is destroyed on drop — no `Roomler Virtual Input` left in `/sys/devices/virtual/input` after the run. Host returned to XFCE with `backend=scrap` and damage tracking active |
| 2026-08-30 | **P1b — fuse the downscale into the repack** | ✅ 4K `Auto`: **52.9 ms → 24.0 ms**, i.e. *faster than not downscaling* (43.8 ms) — the write is 4× smaller while the read stays sequential. ~30 fps at 4K instead of ~19. ⚠️⚠️ **The first attempt made it 6× WORSE (329.8 ms)**: sampling two source rows a pitch apart per output pixel, because **the scanout mapping punishes strided reads brutally**. Row-buffering into cached scratch — sequential reads, identical arithmetic — is what won. A unit test pins the fused output byte-for-byte against the two-step route it replaced |
| 2026-08-30 | **end-to-end browser session — ATTEMPTED, blocked** | ⚠️ Swapping the FR-36 build in as the daemon failed: the host's **auto-start hook respawned the packaged `roomlerd run` (no `--config`) within ~3 s**, retook the single-instance lock, and the FR-36 binary exited at once. ⚠️ `systemctl stop roomlerd` also **killed the swap script itself** — a `setsid`-detached child of a `roomler exec` is still in the unit's cgroup, and systemd kills the cgroup. Use a `systemd-run` transient unit. Host restored to XFCE + the packaged daemon (`NRestarts=0`, one process, no lock refusals) — cleaner than it was found, since the long-running orphan is gone |
| 2026-08-30 | **🏆 END-TO-END BROWSER SESSION — PASSED** | The `roomler.ai` viewer rendered `scw-m2-asahi`'s **GNOME Wayland** desktop (`connected`, H.264 SW, ~16 fps, **2048×1080** for a 4096×2160 panel ⇒ the fused downscale fed the encoder). Daemon log for that session: `capture: backend=drm … node="/dev/dri/card2" 4096x2160` + `input: backend=uinput`. **Gates came from CONFIG, not env** (`config-backed env fallbacks registered keys=[…DRM_CAPTURE…UINPUT]`) — decisive, because the serving daemon was spawned by the host's auto-start hook *outside systemd*, where a unit env block could not have reached it. A browser click opened **GNOME Shell's own calendar panel**; `Escape` closed it. ⚠️ Typing did NOT arrive — the viewer sends `KeyText`, which the backend drops by design: **navigate yes, type no** |
| 2026-08-30 | how the blocker was cleared | The auto-updater had already installed release **0.4.30**, which carries the merged FR-36 stack — so the test ran against the **shipped artifact**, not a dev build, and no binary swap was needed after all. Gates were set with `roomlerd cli config set`. ⚠️ A dead-man switch (`systemd-run --on-active=…` restoring the packaged service) was armed throughout; the host briefly went offline during a bad `systemd-run` invocation (`--config` was swallowed as a systemd-run option — it needs `--`) and the hook restored it within seconds |
| 2026-08-30 | **🏆 P4b — typing works through the browser** | Typed `echo FR36-TYPED-OK-123` in the viewer → **exactly that appeared at the remote GNOME Wayland terminal prompt**, `Enter` ran it, the shell echoed the result. Uppercase, digits and punctuation all correct ⇒ shift handling right. Daemon: `uinput: typed text will be sent as physical keys for this layout layout="us" detected="us"`. Full round trip: browser → WebRTC → roomlerd → uinput → evdev → libinput → mutter → terminal → bash. ⚠️ The first two attempts showed nothing and the code was NOT at fault — typing on a bare GNOME desktop does nothing (no focus), and GNOME 48 has no Activities button to click. Putting a real terminal on the desktop was what made the test decisive |
| 2026-08-30 | **🏆 survives a reboot, nobody logged in** | Cold boot, autologin disabled ⇒ `loginctl` shows only a `greeter` session for `lightdm`. The browser rendered **the lightdm greeter** at `connected`, 26 fps, 1920×1080. Gates survived in `/etc/roomler/config.toml` — the payoff for making them config keys rather than env |
<!-- RETIRED-NAME-ANCHOR(6): `meshharbor-agent.service` is named deliberately —
     it is the retired-name systemd unit that was still ENABLED on this host
     and racing `meshharbord.service` for the single-instance lock. The unit
     literally exists under that name on pre-rename machines, so an operator
     hunting this restart storm must be able to grep for it. FR-21 / FR-36. -->

| 2026-08-30 | **root cause of this host's restart storm — FOUND and FIXED** | Not an "auto-start hook": **two units**. `meshharbor-agent.service` (the RETIRED name, `ExecStart=/usr/bin/roomlerd run`, no `--config`) was still **enabled** and owned the live process, while `meshharbord.service` (current name, `--config`) was disabled. They race for the single-instance lock. ⚠️ **Every `systemctl start roomlerd` I ran during this FR started the second unit to fight the first** — I was generating the storms I was diagnosing. Fixed by `disable roomler-agent` + `enable roomlerd`; verified across a second reboot: one daemon, under `meshharbord.service`, **0 lock refusals since boot** |
