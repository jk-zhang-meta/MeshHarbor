# FR-45 — Portal capture: Wayland where there is no scanout

**Issue:** [#1041](https://github.com/gjovanov/roomler-ai/issues/1041) · **Status:** P1 → P3c COMPLETE and field-verified — **a Wayland desktop is captured through the portal and delivered to the daemon as a correct picture**. **P4 (RemoteDesktop input) FIELD-VERIFIED** — injection lands to the exact requested pixel, scroll sign correct, restore round trip clean. **P5 (mutter direct) FIELD-VERIFIED on WSL2, through the daemon's own cascade, encoding with `av1_nvenc` at native 1920×1080 in 11.4 ms — AC2 met** (2026-09-25). **Docs:** [`docs/linux-capture.md`](../linux-capture.md) · **Owner:** agent / capture

## Goal

Capture a **Wayland desktop that has no DRM scanout** — WSL2, containers,
nested compositors, cloud VMs with no display controller — via
`xdg-desktop-portal`'s ScreenCast interface and PipeWire.

[FR-36](FR-36-wayland-capture.md) closed by capturing **below** the compositor
with DRM/KMS. That works and is the right answer for unattended access, but it
requires a real CRTC with live scanout. Where there is none, there is nothing
to read, and no amount of configuration creates one.

## Why now — the two halves are measured and they do not meet

| | Wayland desktop | DRM scanout | HW encode |
|---|---|---|---|
| `scw-m2-asahi` (Apple Silicon) | ✅ | ✅ `apple-drm`, 4096×2160 | ❌ **none** — Asahi has no video-encode driver (no `/dev/video*`, no `/dev/media*`, no AVD/encode module) |
| WSL2 on an RTX-class laptop | ✅ (nested GNOME under WSLg) | ❌ **`/dev/dri` does not exist** | ✅ `av1_nvenc` / `hevc_nvenc` / `h264_nvenc`, measured `avg_encode_ms=10.4` |

So today the only host that can *capture* Wayland cannot *encode* in hardware,
and the only host that can encode in hardware cannot be captured. **The portal
is the one path that joins them**, and it is the path FR-36 deliberately
demoted to a fallback and never built.

Measured on WSL2 2026-08-31 through the Xvfb virtual desktop, to show the
encode half already works there:

```
AV1 4:2:0 HW (av1_nvenc) · dec HW · 1920×1080 · 77 kbps · ~41 ms
avg_encode_ms=10.4     (Asahi software openh264: 15–21)
```

## ⚠️⚠️ This is the ATTENDED path. It must never be sold as unattended.

FR-36's P0 established this and it has not changed:

- ScreenCast needs an **interactive picker** and an **active user session**.
- `restore_token` only avoids re-prompting *after a human approved once*.
- **While the session is LOCKED, mutter refuses to create *or restore* a
  screencast**, and the failed attempt tends to **consume the saved token**.
- Token behaviour is **inconsistent across compositors**; reboot/logout
  invalidates it.

So this FR does **not** replace FR-36 and does not deliver greeter or
locked-screen capture. It serves the case FR-36 cannot reach: a logged-in user
on a machine with no scanout. The backend priority stays
**DRM/KMS → portal → X11**, with the portal picked only when DRM finds no CRTC.

## Design

| Phase | What | Kill switch |
|---|---|---|
| **P1** ✅ | Detect whether `org.freedesktop.portal.ScreenCast` is actually exposed, and report WHY not, in `capture-smoke` (`capture/portal.rs`). Uses zbus, which is pure Rust and adds no system `.so`. | n/a (read-only) |
| **P2a** ✅ | `portal-helper` hidden subcommand, spawned as the console user with that session's bus. Proven by running `detect()` from the daemon and getting `available` where it previously could only say `no-session-bus`. ⚠️ Built with the verified **privilege drop**, not `systemd-run` as planned — see below. | `MESHHARBORD_PORTAL_CAPTURE=0` |
| **P2b** ✅ | The helper opens the ScreenCast session: `CreateSession` → `SelectSources` → `Start` → `OpenPipeWireRemote`, giving a PipeWire node id. Consent handled via `persist_mode`/`restore_token`. ⚠️ The fd **stays in the helper**, and so does the token — see the corrected decisions below. Field-verified end to end: root → helper → live session, **15 ms, no dialog**. | `MESHHARBORD_PORTAL_CAPTURE=0` |
| **P3a** ✅ | Reach `libpipewire` by **`dlopen`**, never a link, and connect the portal's fd to it. Verified three ways: **0** `DT_NEEDED` entries on x86_64 AND aarch64; a live connect (`libpipewire 1.4.11`); and graceful degradation with the library hidden in a mount namespace. Zero new dependencies. | same |
| **P3b-i** ✅ | SPA POD serialisation in Rust. Forced, not chosen: `nm -D --defined-only libpipewire-0.3.so.0 \| grep -c '^spa_'` is **0**, because the whole builder API is `static inline` — there is nothing to `dlsym`, and linking would undo P3a. Byte-exact tests against the header layout, and **validated by PipeWire in P3b-ii** — the daemon parsed it and answered with a fixated format. | same |
| **P3b-ii** ✅ | `pw_stream_new`/`add_listener`/`connect` with the EnumFormat param, and the parser `param_changed` needs. **This validates P3b-i** — PipeWire parsed the hand-written POD. Field-verified as root: **negotiated BGRx 1920x1080 (libpipewire 1.4.11) in 12 ms**, and BGRx was our first preference. | same |
| **P3c-i** ✅ | `process` → `pw_stream_dequeue_buffer` → inspect → queue back. **A picture exists.** Field-verified as root: 3 frames, **MemFd**, stride 7680 (= 1920x4), 8 294 400 bytes (= a full frame), **8291/8320 sampled bytes non-zero**, and the checksum CHANGES between runs — live pixels, not a constant. | same |
| **P3c-ii** ✅ | Frames to the daemon and the **sixth `ScreenCapture` backend**, picked after DRM and before X11. ⚠️ A pipe and a copy, **not** `SCM_RIGHTS` — see the corrected decision below. Field-verified through `capture-smoke` as root: `backend=portal`, **delivered=5 empty=0**, 1920x1080 Bgra, `mean_ms=27.70`, and the dumped frame is a correct picture. | `MESHHARBORD_PORTAL_CAPTURE=1` |
| **P4** ✅ (2026-09-01, field-verified on Asahi/GNOME) | Input via the portal's **RemoteDesktop** interface, riding the SAME session as capture — `CreateSession`/`Start` move to RemoteDesktop, `SelectDevices` (keyboard+pointer, persist on v2+) slots in before the unchanged `SelectSources`, so ONE consent dialog covers see+touch and one restore token covers both (stored apart from the capture-only token: `portal-restore-token-rd`). The daemon's input arbiter forwards `InputMsg` JSON lines to the helper's stdin; the helper maps them to `Notify*` (evdev keycodes via the shared FR-36 table; typed text as Unicode keysyms, layout-proof; absolute motion in the stream's LOGICAL size). Falls back to capture-only where the portal has no RemoteDesktop (wlr, measured). Motivation measured 2026-08-31: uinput works in WSL2 and libinput even enumerates the device — but a NESTED compositor reads its parent, not evdev, so nothing consumes the events. | `MESHHARBORD_PORTAL_INPUT=0` (config `portal_input`) |
| **P5** ✅ (2026-09-01, field-verified on BOTH hosts) | **`org.gnome.Mutter.ScreenCast` DIRECT — the unattended sibling, for hosts the portal cannot serve.** Mutter's own API needs no portal backend and shows no consent dialog, which is exactly what blocks WSL2 (where `xdg-desktop-portal-gnome` exits without a GNOME session, while `mutter --headless` runs fine and exposes ScreenCast v4). Same PipeWire consumption, same POD negotiation, same wire format and `ScreenCapture` backend — only the *session broker* changes. ⚠️⚠️ **This is NOT a portal variant and must never be described as one: it does not ask.** Its peer is FR-36's DRM backend (also unattended, also opt-in), not P2b. | `MESHHARBORD_MUTTER_CAPTURE` (config `mutter_capture`), default **OFF** |
| **Docs** ✅ (2026-09-25, added retroactively — see the criterion) | [`docs/linux-capture.md`](../linux-capture.md): the Linux capture cascade and its four arms, the attended-only rule, the logind gate (P5b), the knobs and the probe-trigger they share; the Linux rows of `remote-control.md` §5.1 and §6.1 and the cascade paragraph + probe-cache warning in `encoders.md` brought up to date; a `docs/README.md` row. | n/a |

### The seam is unchanged

`ScreenCapture` (`capture/mod.rs`), chosen in `open_default`. DRM is the fifth
backend; this is the sixth. No pump changes.

## ⚠️ The dependency question is the biggest design risk, and it is not theoretical

FR-36 P4b rejected `libxkbcommon` on exactly these grounds and the same
reasoning applies harder here: **linking `libpipewire` would put it in
`roomlerd`'s `DT_NEEDED` on every Linux build.** Headless fleet hosts —
cluster nodes, containers, the ones that will never run a portal — have no
reason to carry it, and a missing `.so` does not degrade a feature: **the
loader refuses to start the daemon at all.** This project has already paid for
that once, when vendored FFmpeg dylibs baked a Homebrew path into the macOS
agent and dyld killed it at launch on every end-user Mac.

Three options, in the order they should be evaluated:

1. **`dlopen` at runtime** behind the existing feature gate — the daemon starts
   everywhere and the backend simply reports unavailable where the library is
   absent. Most code, least deployment risk.
2. **A separate helper binary** that links PipeWire and streams frames over a
   socket, spawned via `current_exe()` — the `caps-probe` precedent
   (`main.rs`, `#[command(hide = true)]`), so no new packaged artifact. The
   daemon's own graph stays clean.
3. Link it directly and accept a hard runtime dependency. **Only if** the
   `.deb`/`.pkg` can be made to carry it, and even then it costs every headless
   host disk and risk for nothing.

⚠️ Whichever is chosen, **prove it by starting the daemon on a host without
PipeWire installed**, not by reasoning about it.


## P5 — the mutter-direct path, and the property it trades away

P4 finished the ATTENDED story. P5 exists because the attended story cannot
reach the host this FR was opened for: on WSL2 `xdg-desktop-portal-gnome` exits
immediately without a real GNOME session, so `CreateSession` fails with
`StartServiceByName … Timeout was reached` — while **`mutter --headless` runs
there perfectly and exposes `org.gnome.Mutter.ScreenCast` v4** (measured
2026-09-01). The portal is the obstacle, not the compositor.

**What changes:** only the session broker. `CreateSession` → `RecordMonitor` →
`Start`, and the node id arrives on the stream object's `PipeWireStreamAdded`
signal. Everything downstream — the SPA POD negotiation, buffer handling, the
frame wire format, the `ScreenCapture` backend — is the P3 code unchanged.

**What it trades away, and why that is acceptable here:**

- ⚠️⚠️ **There is no consent dialog.** `org.gnome.Mutter.ScreenCast` is a
  privileged session API: anything on the user's session bus may call it. So
  this path captures **without asking**, and the spec's "ATTENDED only" warning
  does **not** apply to it — that warning is about P2b and must not be quietly
  transferred onto a path that behaves differently.
- It is not a privilege escalation. Anything that can reach that bus is already
  running as the session user and can screenshot at will; the daemon is root and
  could read the framebuffer regardless. The honest framing is that this is the
  **unattended sibling of FR-36's DRM backend** — same bargain, different
  mechanism — and it is gated the same way: opt-in, default OFF.
- ⚠️ It is **GNOME-specific**. No KDE or wlroots equivalent is implied; those
  hosts keep the portal path.

**Why it could not be prototyped in a shell**: a mutter screencast session is
owned by the D-Bus connection that created it and dies when that connection
closes, so `busctl` (a fresh connection per call) can never hold one open — the
same rule `screencast::Session::_conn` exists for. Proving it needed code, which
is what this phase is.

## ⚠️⚠️ P1 found the thing that shapes P2, and it is not PipeWire

**The daemon runs as root and has no D-Bus session bus.** Detection from the
daemon's own context returns `no-session-bus` on a host whose GNOME Wayland
session is right there and active. That is not a test artefact — the portal is
**per user session** by construction, and a root daemon is not in one.

So **P2/P3 need a session-resident component before they need a single line of
PipeWire code**: something running as the logged-in user that opens the portal
session and hands the result back to the daemon. That partially resurrects the
"session broker" FR-36 superseded — legitimately this time, because FR-45 *is*
the attended path, and the reason FR-36 rejected it (it made the portal
reachable but the portal refuses when locked) does not apply to a case that
never claimed to work locked.

⚠️ **And a second, harder blocker.** On `scw-m2-asahi`, running **inside** the
active GNOME Wayland session with `xdg-desktop-portal-gnome` installed, the
portal exposes **neither `ScreenCast` nor `RemoteDesktop`** — verified
independently with `busctl`, which lists Account, Camera, FileChooser,
Notification and eleven others but not those two. FR-36 measured the same thing
and attributed it to an X11 session; it reproduces under Wayland, so that
explanation was wrong. **P2 cannot start until this is understood**, because
there is currently no host in the fleet that offers the interface P2 would
call.


## ✅ The P2 blocker is diagnosed and cleared (2026-08-31)

`scw-m2-asahi` exposed no ScreenCast for a reason that had nothing to do with
the session type FR-36 blamed, and nothing to do with a missing package:

1. `XDG_CURRENT_DESKTOP=GNOME`, `XDG_SESSION_TYPE=wayland`, `gnome.portal`
   installed, and **mutter was already exposing its own
   `org.gnome.Mutter.ScreenCast` / `RemoteDesktop` APIs** — the compositor side
   was never the problem.
2. **`xdg-desktop-portal-gnome` was `inactive (dead)`.** It is a `static`,
   D-Bus-activated unit and nothing in that session had triggered it, so the
   frontend served only the interfaces it can provide alone (Account, Camera,
   FileChooser, Notification …).
3. ⚠️ **Starting the backend was not enough.** The frontend caches its backend
   selection at startup; the interfaces appeared only after
   `systemctl --user restart xdg-desktop-portal` *with the backend already up*.

```
portal=available (screencast v5, remote_desktop=true)
```

⇒ **P2 is unblocked**, `RemoteDesktop` is present so **P4 is viable**, and the
`Available` branch of the P1 detector — the one branch that had never been
exercised — is verified.

⚠️ **The ordering fragility is itself a design input.** A host can have every
package installed and still offer nothing, depending on service start order, so
the agent must **detect at session time and never cache** the answer. The P1
advice string was corrected accordingly: it used to say "install the backend",
which on this host would have sent the reader to a package that was already
there.


## P2 plan — the session-resident component already exists as a pattern

P1 found that the daemon is root and has no session bus. The obvious reading is
"FR-45 needs a broker written". It does not: `agents/meshharbord/src/companion.rs`
already spawns a process **as the console user with the session bus wired up**,
and has done since FR-27 used it as a consent-prompt surface.

The Linux arm (`#[cfg(all(unix, not(target_os = "macos")))]`) does exactly what
P2 needs:

```rust
Command::new("systemd-run")
    --uid={sess.uid}
    --setenv=XDG_RUNTIME_DIR=/run/user/{uid}
    --setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus
```

That is the same environment that had to be hand-built as
`runuser -u m1 -- env XDG_RUNTIME_DIR=… DBUS_SESSION_BUS_ADDRESS=…` to make P1
detection succeed at all. `graphical_session()` already resolves the session
and uid; there is nothing to invent.

### 🔑 And it answers the dependency question — but only in one combination

| shape | session context | `DT_NEEDED` on the daemon |
|---|---|---|
| link PipeWire into the daemon | ❌ no session bus | ⛔ **stops headless daemons starting** |
| hidden subcommand of the same binary, PipeWire **linked** | ✅ | ⛔ **same binary, same `DT_NEEDED`** |
| separate helper binary | ✅ | ✅ but a new packaged artifact + version skew |
| **hidden subcommand + `dlopen`** | ✅ | ✅ |

⚠️ The middle row is the trap worth naming: a helper *subcommand* does **not**
by itself solve the linkage problem, because it is the same ELF. Only `dlopen`
(or a genuinely separate binary) does. **`roomlerd portal-helper` +
`dlopen(libpipewire)`** takes the session context from the companion pattern and
the deployment safety from `dlopen`, with no new artifact — the `caps-probe`
precedent (`current_exe()`, `#[command(hide = true)]`).

### Phases as they now stand

- **P2a** ✅ **shipped and field-verified** (#1054) — `portal-helper` hidden
  subcommand; the daemon spawns itself as the console user pointed at that
  session's bus, the child reports one `MESHHARBOR_PORTAL_JSON:{…}` line, and
  `detect_in_session()` parses it back.

  ⚠️ **Departed from the plan above, deliberately.** #1050 said `systemd-run
  --uid`, mirroring the consent companion. It is spawned as a **direct child
  with the verified privilege drop** instead, for two reasons P2b needs: a
  direct child can be handed the PipeWire fd over `SCM_RIGHTS` on a
  socketpair, and it dies with the daemon that owns it. It also drops
  privilege without depending on systemd being the init system. Not
  `CommandExt::uid()` — that leaves the child in root's supplementary groups,
  a silent retention bug rather than a visible failure.

  🔑 **The near-miss this phase existed to avoid is still live for P3**: a
  helper *subcommand* does not by itself solve the dependency problem, because
  it is the same ELF and so the same `DT_NEEDED`. The subcommand bought the
  session context; only `dlopen` buys the linkage.
- **P2b** ✅ **shipped and field-verified end to end** (#1059) —
  `CreateSession` → `SelectSources` → `Start` → `OpenPipeWireRemote`.

  ⚠️⚠️ **This plan contradicted itself and the contradiction is now resolved.**
  It said P2b passes the PipeWire fd to the daemon over `SCM_RIGHTS` (inherited
  from FR-36's design) *and* that P3 consumes PipeWire inside the helper. Those
  cannot both be true. Decided:

  > **The helper consumes PipeWire. The fd never crosses to the daemon.**

  1. **Fault isolation** — the `encode::caps` lesson exactly: third-party
     driver code that faults inside the daemon costs a crash-loop, not a
     degraded feature. `libpipewire` loads SPA plugins on vendor GPU stacks.
  2. **It is not slower** — PipeWire negotiates a *pool* of buffers, so those
     fds cross once and per frame only "buffer N is ready" flows. Frames
     crossing a process boundary is not pixels being copied.
  3. **The helper already runs as the session's user**, whose PipeWire it is.

  `SCM_RIGHTS` therefore moves to P3, carrying **buffer** fds.
- **P3a** ✅ **shipped and field-verified** (#1062) — `dlopen` reaches
  `libpipewire`, and the portal's fd connects to it. The daemon never links it,
  and after the P2b decision never connects to it either.

  🔑 **Proven by construction, not by finding a bare host.** `readelf -d` shows
  **zero** `DT_NEEDED` entries matching `pipewire`/`libspa` on both
  architectures — if it is not a load-time dependency, the loader never looks
  for it, which is stronger than testing one host that happens to lack it.
  Graceful degradation was then shown *live* by bind-mounting the library away
  inside a mount namespace: the binary ran, the portal handshake still
  succeeded, and PipeWire reported unavailable naming the sonames it tried.

  ⚠️ It does **not** prove frames flow. That is P3b, and a non-null pointer is
  not a picture.
- **P3b** — format negotiation (SPA PODs) and buffer delivery, then the sixth
  `ScreenCapture` backend.
- **P4** — RemoteDesktop input in the same helper and the same session. BUILT
  2026-09-01; the design decisions worth knowing before editing:
  - **One session, both halves.** `SessionKind::WithInput` re-homes
    `CreateSession`/`Start` onto RemoteDesktop and adds `SelectDevices`;
    `SelectSources`/`OpenPipeWireRemote` stay on ScreenCast against the shared
    session path. One dialog, one token, one PipeWire node.
  - **The input wire is `InputMsg` JSON lines on the helper's stdin.** Same
    binary both ends, serde already on the type, so no second wire enum and no
    version-skew surface; an unparseable line costs that event only.
  - **Routing is per-event, not per-backend-choice**
    (`portal::input_route::try_route` in the arbiter's single inject funnel):
    the OS injector is created lazily at the FIRST event while the portal
    capture opens concurrently, so a one-time choice would race startup.
    Registration is generation-checked so a stale capture `Drop` cannot tear
    down its successor's route. Overload DROPS rather than falling through —
    splitting one gesture across two injection backends is worse than a lost
    event.
  - **Keys are evdev keycodes** (`NotifyKeyboardKeycode`, the shared
    `input::hid_evdev` table FR-36 built — moved out of the uinput backend
    because the two consumers sit behind different features). **Typed text is
    Unicode keysyms** (`NotifyKeyboardKeysym`, codepoint+0x01000000 above
    Latin-1) — layout-proof, the exact property the uinput backend cannot
    offer.
  - **Absolute motion is addressed in the stream's LOGICAL size** (the
    portal's advertised stream size), not the negotiated pixel size — they
    differ under a HiDPI scale factor. Wire coords are normalised 0..1, so
    the conversion is one multiply in the helper.
  - ⚠️ **Axis sign follows libinput (positive = down/right), NOT evdev** —
    copying the uinput backend's REL_WHEEL inversion here scrolls backwards.
    Pinned by a unit test; still needs a field check.
  - ⚠️ `MESHHARBORD_PORTAL_INPUT` defaults **ON** (unlike the capture flag): it
    is inert unless a portal capture is already live, and on those hosts the
    portal is the only input path with a reader behind it — a capture-only
    default would ship a read-only session and call it working.

## Acceptance criteria

- [x] ✅ **MET by P5, 2026-09-01 — a Wayland desktop IS captured in WSL2.**
      Not through the portal, which cannot work there
      (`xdg-desktop-portal-gnome` exits without a GNOME session), but through
      `org.gnome.Mutter.ScreenCast` directly against a headless mutter:
      **node 32 on `Meta-0`, ScreenCast v4, session open in 28 ms, BGRx
      1920×1080, 4.92 GB of frames, 2025/2025 sampled bytes non-zero and frame
      2 ≠ frame 1** — with NO portal backend on the bus at all. ⚠️ It is
      UNATTENDED (no consent dialog) and GNOME-specific. The original wording
      of this criterion — a nested GNOME session in the browser — is NOT what
      was achieved and is not reachable: `mutter --nested` hangs on WSLg's
      ancient compositor. A
      **nested GNOME Wayland session in WSL2** (per the WSLg + `gnome-shell
      --nested` recipe) is captured and rendered in the browser
- [x] That session encodes with **`*_nvenc`**, and `avg_encode_ms` is within
      ~2× the 10.4 ms already measured on that host. **MET 2026-09-25 on
      0.4.102, like for like at 1920×1080.** The P5 mutter-direct capture,
      driven from a signed-in browser controller through the daemon's **own**
      cascade (`mutter node 44 on Meta-0` → `capture: backend=portal …
      1920×1080`, virtual desktop OFF, so not the Xvfb fallback), encoded with
      **`av1_nvenc`** at **`avg_encode_ms` mean 11.39 ms** (min 6.24, max
      16.73) over **109 agent-side `DC pump heartbeat`s across 5 sessions, every
      one at 1920×1080**; the two sustained sessions (~60 s and ~2.2 min)
      averaged 12.00 and 11.66 ms — **1.1–1.15× the 10.4 ms baseline**, inside
      the ~2× bound, and
      the viewer's HUD agreed (`1920×1080`, `AV1 4:2:0 HW (av1_nvenc) · relay ·
      dec HW`). Condition, stated because it is load-bearing: the FR-59 P5
      slow-link opening profile OFF (`MESHHARBORD_SLOW_LINK_PROFILE=0`) and the
      pair's remembered rate cleared — the 2026-08-31 baseline predates that
      profile, so this IS the baseline's condition. The earlier reading of the
      same day — **8.25 ms at 1280×720** (68 heartbeats / 6 sessions), the
      size the profile had opened at — stands beside it as the smaller-frame
      number, and the wrong turn between the two (a knob change that forced a
      capability probe which hung under the rig's load) is in the field log
- [x] `roomlerd capture-smoke` reports **whether the portal is available and
      why not**, on a host where it is absent — FR-36 measured a host where
      `xdg-desktop-portal` was running yet exposed **neither ScreenCast nor
      RemoteDesktop**, so availability must be *detected*, never assumed
- [x] **The daemon still starts on a host with no PipeWire library present.**
      Verified by running it, not by inspection — `dlopen` only, **0**
      `DT_NEEDED` entries on both architectures, and a live run with the
      library bind-mounted away that still completed the portal handshake
- [x] Backend order holds: a host with a real CRTC still picks **DRM**, and the
      portal is chosen only when DRM finds none — measured on a host that has
      BOTH: DRM-only → `backend=drm`; **both flags → still `backend=drm`**;
      neither → the portal does not engage at all (no helper, no dialog)
- [x] X11/Windows/macOS unchanged; the kill switch restores the current
      cascade — with no flag set the cascade is byte-for-byte what it was, and
      the portal code is Linux-only, feature-gated AND env-gated, so it cannot
      reach the other platforms. Windows/macOS CI lanes green throughout
- [x] Field-verified with the **before** state recorded beside the after — done for P2a (`no-session-bus` → `available`, with an in-session control); each later phase repeats it
- [ ] The spec and the UI both say **attended-only** — no greeter, no locked
      screen
- [x] **P4: input lands.** Field-verified on `scw-m2-asahi` (GNOME Wayland,
      RemoteDesktop v2), measured against DRM capture as ground truth: three
      `mouse_move` events landed at **(480,270) for 0.25/0.25**, **(1440,648)
      for 0.75/0.6** and **(1152,216) for 0.6/0.2** — exact to the cursor
      hotspot. **Scroll sign CONFIRMED**: `dy:+4` line-mode scrolled the page
      DOWN (video title → comments), so the libinput convention holds and the
      evdev inversion would have been backwards. **Click and BOTH keyboard
      paths verified too** (2026-09-01): a click focused a text editor and
      placed the caret; `Key` (HID→evdev) typed `abc`; `KeyText` typed ASCII;
      and Ctrl+S — a modifier HELD across another key — saved the file, which
      is what makes it objective rather than a reading of pixels. ⚠️ `KeyText`
      is NOT layout-proof: see the keysym row in the field log
- [x] **P4: one dialog, then none.** First session prompted once; the second,
      after a full helper restart, came up `input_ok:true` in seconds with **no
      dialog**, restoring from `portal-restore-token-rd` — and injection landed
      again in that restored session
- [x] **Docs updated/created with diagrams, linked from `docs/README.md`** —
      [`docs/linux-capture.md`](../linux-capture.md): the Linux capture cascade
      and why each arm is opt-in, the portal handshake and the mutter broker as
      `mermaid` sequence diagrams, the helper/`dlopen` dependency rule, input on
      the same session, the **attended-only rule** and every place the product
      states it, portal detection and its five verdicts, the logind session
      gate that keeps P5 off WSL2 and headless hosts (open decision P5b) with
      the transient-unit recipe, the field table, the configuration keys and
      the caps-probe trigger they all share; `file:line` anchors verified
      against master. Indexed in `docs/README.md`, and cross-linked from
      `remote-control.md` §5.1 / §6.1 and `encoders.md` (capture backends, the
      probe cache). ⚠️ **Added retroactively (2026-09-25)**: FR-45 opened on
      2026-08-31, before the docs-before-close rule (#1401, 2026-09-05), and a
      close after that date binds it. Marked rather than backdated, so the spec
      does not claim it always complied.

## Open decisions

- ✅ ~~**Which of the three dependency shapes.**~~ **Decided: hidden subcommand +
  `dlopen`.** A helper subcommand alone does NOT solve the linkage problem — it
  is the same ELF, so the same `DT_NEEDED`. Only `dlopen` (or a separate binary,
  which costs an artifact and version skew) does. See the P2 plan table.
- ✅ ~~**Does `/dev/uinput` work in WSL2?**~~ **ANSWERED 2026-08-31 — P4 is
  MANDATORY, and the reason is not the one expected.**
  - uinput itself works: `CONFIG_INPUT_UINPUT=m`, module loads, FR-36's
    injector creates a device (`has_permission=true`).
  - The evdev subsystem works too — a *persistent* uinput device appears as
    `/dev/input/event0` and **libinput enumerates it on `seat0`**. `/dev/input/`
    is normally empty only because nothing has created a device, not because
    the subsystem is missing. (⚠️ FR-36's injector destroys its device on drop,
    so a quick `ls` afterwards shows nothing and reads as failure.)
  - **But a NESTED compositor does not read evdev.** Weston under WSLg loads
    `wayland-backend.so` and uses `xdg_wm_base` — no libinput, no udev, no
    device enumeration. A nested compositor takes input from its **parent**,
    and WSL2 can only run nested or headless compositors because there is no
    DRM to run a libinput-backed seat on.
  ⇒ Injected events are published and nothing consumes them. **The portal's
  RemoteDesktop interface is the only input path for this case**, which makes
  ScreenCast + RemoteDesktop a coherent pair rather than capture-only.
  2026-08-31: `CONFIG_INPUT_UINPUT=m`, the module loads, and FR-36's injector
  created a device and accepted a pointer move (`input: backend=uinput`,
  `has_permission=true`). So injection is not the obstacle.
  ⚠️⚠️ **`/dev/input/` is otherwise EMPTY on WSL2** — no evdev devices at all,
  because WSLg's input arrives over RDP rather than from libinput. A uinput
  device therefore publishes events that, on present evidence, **nothing in
  WSL2 consumes**. So P4 probably survives — not because uinput fails, but
  because the reader is missing.
  **Still unproven, and it is the thing to test first:** whether a *nested*
  compositor (`gnome-shell --nested` under WSLg) reads evdev. If it does, P4
  disappears; if it does not, the portal's RemoteDesktop interface is the only
  input path and P4 is mandatory. One nested session answers it.
- **P5b — session resolution for hosts with no graphical logind session.**
  Surfaced 2026-09-25 (field log): as shipped, `mutter_capture` cannot serve a
  host whose compositor user has no `x11`/`wayland` logind session — WSL2, and
  any headless-mutter box — because `helper::spawn_child` resolves the session
  user with `companion::graphical_session()`, written for the *attended*
  portal case. Options: an operator-named override (`portal_session_user` /
  `MESHHARBORD_PORTAL_SESSION_USER`), a fallback to the uid whose session bus owns
  `org.gnome.Mutter.ScreenCast`, or documenting the `PAMName=login` +
  `XDG_SESSION_TYPE=wayland` transient-unit recipe as the supported way.
  Pillar-1 code with its own field verification either way — a decision, not a
  docs tweak.
- **Restore tokens: store or not.** They are per-compositor, invalidated by
  reboot/logout, and a failed locked-session attempt can consume one. Storing a
  token that is silently dead is worse than prompting.
- Multi-monitor selection: the portal's picker returns whichever outputs the
  user chose, not a stable index — the mapping to `DisplayInfo` needs thought.
- Whether the portal path should be offered on hosts that *do* have DRM (e.g.
  as an operator override when DRM capture misbehaves).

## Out of scope

- Replacing FR-36. DRM stays the unattended path and the default where a CRTC
  exists.
- Greeter and locked-screen capture. The portal structurally refuses both.
- macOS/Windows. This is a Linux desktop-portal concern.

## Field-verification log

| date | build | result |
|---|---|---|
| 2026-08-31 | 0.4.33, WSL2 | **`/dev/dri` absent** — DRM capture impossible. `/dev/dxg` + `libnvidia-encode.so` present; caps probe reports `ffmpeg-av1_nvenc`, `ffmpeg-hevc_nvenc`, `ffmpeg-h264_nvenc` on an RTX 5090 |
| 2026-08-31 | 0.4.33, WSL2 | Xvfb virtual desktop + `av1_nvenc`: 1920×1080, `avg_encode_ms=10.4`, 77 kbps idle, ~41 ms. Establishes the encode half works; only capture is missing |
| 2026-08-31 | 0.4.33, Asahi | Wayland captured via DRM at 1920×1080, but **software encode only** — no video-encode driver exists for Apple Silicon on Linux |
| 2026-08-31 | 0.4.33, WSL2 | **uinput measured, and it reframes P4.** `CONFIG_INPUT_UINPUT=m`, module loads, FR-36's injector created a device and accepted a move (`has_permission=true`) — injection is not the obstacle. But `/dev/input/` is **empty** (WSLg takes input over RDP, not evdev), so nothing appears to consume those events. P4 likely survives because the *reader* is missing, not the writer. Untested: whether a nested `gnome-shell` reads evdev |
| 2026-08-31 | 0.4.33 + weston 13, WSL2 | **The nested-compositor input question, ANSWERED.** A persistent uinput device appears as `/dev/input/event0` and **libinput enumerates it on `seat0`** — so the evdev subsystem is fully alive in WSL2. But weston under WSLg loads `wayland-backend.so` / `xdg_wm_base` with **no libinput, no udev, no device enumeration**: a nested compositor reads its PARENT, not evdev. And WSL2 can only run nested or headless compositors, having no DRM to host a libinput seat. ⇒ **P4 is mandatory**; the portal's RemoteDesktop is the only input path here |
| 2026-08-31 | P1, WSL2 | `portal=no-screencast — xdg-desktop-portal is running but exposes no ScreenCast — install the backend matching your compositor`. The FR-36 case, now named rather than guessed at |
| 2026-08-31 | P1, Asahi **as root** | `portal=no-session-bus`. ⚠️ **This is the architecture, not a test artefact** — the daemon is root, the portal is per-user-session, so P2/P3 need a session-resident component before any PipeWire code |
| 2026-08-31 | P1, Asahi **inside the GNOME Wayland session** | `portal=no-screencast`, **independently confirmed with `busctl`** (lists Account, Camera, FileChooser, Notification … but neither ScreenCast nor RemoteDesktop) despite `xdg-desktop-portal-gnome` being installed. ⛔ **No fleet host currently exposes the interface P2 would call.** FR-36 blamed an X11 session for this; it reproduces under Wayland, so that explanation was wrong |
| 2026-08-31 | **P2 blocker diagnosed and cleared** | Not the session type (FR-36's guess) and not a missing package. `xdg-desktop-portal-gnome` was `inactive (dead)` — a `static` D-Bus-activated unit nothing had triggered — while mutter was already exposing its own ScreenCast/RemoteDesktop APIs. ⚠️ Starting the backend alone did NOT help: the frontend caches its backend selection at startup and had to be restarted after it. Result: `portal=available (screencast v5, remote_desktop=true)` — P2 unblocked, P4 viable, and the detector's `Available` branch exercised for the first time |
| 2026-08-31 | **P2a, Asahi — the loginctl call underneath it never worked** | `loginctl list-sessions --no-legend --no-pager -o value -p Id` — what `graphical_session()` ran — **exits 1 with empty stdout**, measured on systemd **255** (Ubuntu 24.04, two hosts) and **257** (Fedora 42): those are `show-*` options and `list-sessions` rejects them. The function read that as an empty session list, i.e. “nobody is at this machine's screen”, on every Linux host, always. ⚠️ The column layout also differs between the two releases (257 inserts `LEADER` and `CLASS`), so only column one is safe to parse; both real samples are now in a test |
| 2026-08-31 | **P2a FIELD-VERIFIED — 0.4.37, Asahi, GNOME Wayland** | Three runs, one binary. **CONTROL** as `m1` inside the session: `available (screencast v5, remote_desktop=true)`. **BEFORE** as root, plain `detect()` (the P1 behaviour): `no-session-bus`. **AFTER** as root through `detect_in_session()`: `available (screencast v5, remote_desktop=true)` — matching the control exactly. Root's environment was confirmed to carry none of `XDG_RUNTIME_DIR` / `DBUS_SESSION_BUS_ADDRESS` / `DISPLAY` / `WAYLAND_DISPLAY`, i.e. the daemon's own situation. 🔑 The AFTER trace shows **both** halves: the child's own line on inherited stderr, then the parent's parsed verdict |
| 2026-08-31 | P2a — what the loginctl fix could **not** be shown to fix here | The claim that the broken lookup also stopped FR-27's consent companion is **reasoned, not observed on this host**: `meshharbor-desktop` is not installed on Asahi, so `ensure_running_inner` returns `Unsupported` one step BEFORE reaching `graphical_session()` (the daemon log carries 15 “prompts go to the desktop companion” lines and no session-lookup failure). What IS measured: the old command exits 1 on both systemd versions, and P2a — which calls the same function — works only with the fix |
| 2026-08-31 | **P2b — zbus panics inside a tokio runtime, again** | The first field run of the handshake died on `Cannot start a runtime from within a runtime` before making a single portal call. P1's `detect()` already ran its D-Bus work on its own thread for exactly this reason; `open()` was written without the guard. 🔑 The fix put the thread INSIDE `open()` rather than at the call site, so the next entry point cannot reintroduce it — the same shape as the `ResolvedSessionPolicy` lesson: make the mistake unrepresentable, not merely fixed |
| 2026-08-31 | **P2b field-verified through `Start` — Asahi, GNOME Wayland** | The live bus objects are the evidence: `…/session/1_170/roomler_ss_472905_1` (CreateSession succeeded) and `…/request/1_170/roomler_start_472905_3` (Start pending). The pid in both tokens is the helper's, and `1_170` is its unique name `:1.170` mangled per the portal spec — so **the request-path derivation is confirmed in the field**, which matters because getting it wrong hangs forever rather than failing. `xdg-desktop-portal-gnome` up, `Start` outstanding 7+ min: the consent dialog is waiting to be answered |
| 2026-08-31 | P2b — what could **not** be observed | The dialog's VISIBILITY is inferred from the pending `Request` plus a live backend, not seen: GNOME refuses `org.gnome.Shell.Screenshot` to unsandboxed callers, and `capture-smoke` does not wire FR-36's config-gated DRM backend, so the screen could not be photographed. ⚠️ Also: `pkill -x roomlerd` on a host reached over the overlay kills the daemon carrying your own SSH — ~40 s of no access until systemd restarted it |
| 2026-08-31 | **P2b COMPLETE — 0.4.37, Asahi, GNOME Wayland** | Three passes, one binary. **1.** As the user, no stored token: a consent dialog, answered by a human, **1,831,429 ms**; returns `node_id=83`, `1920x1080`, `pipewire_fd_ok=true`, `cursor_mode_used=2` (embedded, of `available_cursor_modes=7`), `available_source_types=7`. **2.** As the user, token stored: **15 ms, no dialog**, `restore_token_sent=true`, same node. **3.** THE PRODUCTION PATH — as **root** through the session helper: **15 ms**, `node_id=83`, `pipewire_fd_ok=true`. 🔑 The 122,000× gap between pass 1 and pass 2 is what makes “did it prompt?” falsifiable rather than asserted. Token file `600 m1`, 36 bytes |
| 2026-08-31 | **P2b — the dialog was NOT where it was looked for** | `Start` sat pending 30 min while the screen showed no dialog. The backend log had the clue — `xdg-desktop-por[392832]: Failed to associate portal window with parent window` — because `parent_window` is `""` for a CLI caller. ⚠️ Diagnosing this needed the product's OWN capture: GNOME refuses `org.gnome.Shell.Screenshot` AND `org.gnome.Shell.Introspect.GetWindows` to unsandboxed callers, so FR-36's DRM backend was the only way to see the screen — via `MESHHARBORD_DRM_CAPTURE=1`, since `capture-smoke` does not register the S2 config fallbacks the daemon does |
| 2026-08-31 | **P2b — the report was carrying the credential** | `SessionReport` documented that the daemon never sees the restore token, and carried it. Noticed because the helper's stdout, redirected to a log for the field test, had the token in plaintext. `open()` now loads and stores it internally and the report says only WHETHER a grant was persisted. 🔑 A caller that cannot hold a credential cannot leak it — stronger than a caller that holds it and is careful |
| 2026-08-31 | **P3a field-verified 3 ways — 0.4.37, Asahi + WSL** | **(a) Structural:** `readelf -d` reports **0** `DT_NEEDED` entries matching `pipewire`/`libspa` on the x86_64 AND aarch64 builds, `ldd` shows nothing, and the binary runs — so the loader can never refuse to start over a library that is not linked. **(b) Success:** `portal-helper --screencast` → `pipewire: connected (libpipewire 1.4.11)` with `node_id=83`, reached entirely through `dlopen`. **(c) Failure:** with `libpipewire-0.3.so.0` bind-mounted over inside a mount namespace, the binary still ran, the portal handshake still succeeded (`node_id=82`, 14 ms) and PipeWire degraded to `unavailable — libpipewire not present (tried …)`. Zero dependencies added |
| 2026-08-31 | P3a — a scare I caused and then disproved | After the namespace test I read `stat -c%s /usr/lib64/libpipewire-0.3.so.0` as **27 bytes** and concluded the bind mount had leaked and broken the host's PipeWire. It had not. ⚠️ **GNU `stat` does not dereference a symlink by default** — that path IS a symlink and 27 is the length of its target string `libpipewire-0.3.so.0.1411.0`; `stat -L` reports the real 797568. `unshare -m` also defaults to PRIVATE propagation, so nothing could have leaked. Library rpm-intact, all three PipeWire services active, and a re-run connected. 🔑 Hiding a library in a mount namespace is a clean, contained way to test a `dlopen` fallback — just measure it with `stat -L` |
| 2026-08-31 | **P3b-ii FIELD-VERIFIED — format negotiated, 0.4.39, Asahi** | `portal-session` as **root**: daemon → privilege-dropped helper → portal session → PipeWire stream → **`negotiated BGRx 1920x1080 @ 0/1 (libpipewire 1.4.11)`** in **12 ms**. 🔑 `video_format=8` is BGRx, the order listed FIRST in our EnumFormat, so the preference was honoured — a stronger signal than “some format came back”. ⚠️ Framerate is `0/1`: GNOME declines to commit to a rate, which is why it is optional in the parse rather than a failure. **This is what validates P3b-i's POD serialisation** — bytes PipeWire accepted, not bytes I believed in |
| 2026-08-31 | **P3b-ii bug 1 — the portal session dies with its D-Bus connection** | First run: `no target node available`. The handshake looked perfect (node id, geometry, usable fd) and the node was ALREADY GONE. A portal session is owned by the connection that created it; `open_blocking` returned, the connection dropped, the portal tore the session down. `Session` now holds it in a field named `_conn` that nothing reads — deleting it “because it is unused” re-breaks capture, and the doc comment says so |
| 2026-08-31 | **P3b-ii bug 2 — SPA writes a SETTLED value as `Choice(None)`** | Second run: `the negotiated video format is not a plain id`. The diagnostic added instead of guessing answered it immediately — `object#40003 id=4 [0x1=Choice 0x2=Choice 0x20001=Choice …]`: **every** property a Choice, `mediaType` included, which can only ever be “video”. 🔑 That is the convention, not a half-finished negotiation — which is why `spa_pod_get_id` unwraps choices. `.fixed()` unwraps kind `None` ONLY; a `Range`/`Enum` still means “not settled” and returns None so the caller keeps waiting, because a range's default is a value nobody agreed to. ⚠️ `param_changed` also fires more than once |
| 2026-08-31 | **P3c-i FIELD-VERIFIED — FRAMES, 0.4.39, Asahi** | `portal-session` as **root**: `negotiated BGRx 1920x1080; 3 frame(s), MemFd stride=7680 8294400 bytes, 8291/8320 sampled bytes non-zero, checksum 0xa4dd8b6e`. Every number is internally consistent — stride = 1920x4, size = 1920x1080x4 — and **MemFd means the buffers are mmap'd, so no GBM import is needed on this host**. 🔑 The checksum CHANGES between runs (`0xe59a9e02` → `0xe459b623` three seconds later): a constant would have meant a stale or zeroed mapping, so this is live pixels off a moving screen. ⇒ **A Wayland desktop with no DRM-based capture is being captured through the portal, from the daemon.** |
| 2026-08-31 | P3c-i — why the report is shaped that way | A black frame and a working capture are BOTH “frames received”, so `frames: 3` alone would have been exactly the unfalsifiable claim this FR keeps rejecting. The report leads with `nonzero_sampled/sampled` + a checksum because those are the only fields that distinguish them. ⚠️ Sampled on a PRIME stride, not read whole: this runs in the `process` callback and a 4K frame is 33 MB. ⚠️ A buffer must be returned with `pw_stream_queue_buffer` on EVERY path — holding them starves the pool and the stream stops silently, looking exactly like a source that produced nothing. ⚠️ `spa_data.fd` is `int64_t`, not `int` |
| 2026-08-31 | **P3c-ii FIELD-VERIFIED — THE BACKEND WORKS, 0.4.40, Asahi** | `capture-smoke` as **root**, the same command that validates DRM and scrap: `capture: backend=portal (MESHHARBORD_PORTAL_CAPTURE=1 … ATTENDED) width=1920 height=1080` then `delivered=5 empty=0 unchanged=0 1920x1080 stride=7680 format=Bgra mean_ms=27.70 worst_ms=34.57`. 🔑 **The dumped frame is a correct picture** — right geometry, right colours (a swapped channel order would have made the sky orange) and the cursor composited in, confirming the `CURSOR_EMBEDDED` request. ⚠️ **Honest limit: this host ALSO has DRM capture.** The portal path is proven; it is NOT yet proven on the host FR-45 was opened for (WSL2, no `/dev/dri`), which still has no ScreenCast backend |
| 2026-08-31 | **P3c-ii — a pipe and a copy, NOT `SCM_RIGHTS`** | The plan's fd-passing is the right OPTIMISATION and the wrong first version. (1) `Frame` owns a `Vec<u8>`, so the daemon copies regardless — fds would save the helper→daemon copy only, not “zero copy” end to end. (2) Passing the compositor's own buffers means NOT queueing them back until the daemon has read them: a per-frame round trip and a stall the compositor can see, and getting it wrong produces **torn frames**, which look like a codec bug. Start correct; optimise when a measurement says to. ⚠️ Both sides DROP rather than block — the helper's `try_send` runs on PipeWire's own thread |
| 2026-08-31 | **Cascade order verified — the portal does not hijack a DRM host** | Three runs on a host that has BOTH: `MESHHARBORD_DRM_CAPTURE=1` → `backend=drm`; **both flags → still `backend=drm`** (DRM first, as documented); neither → the portal never engages — no helper spawned, no dialog. 🔑 Worth measuring rather than assuming: adding a backend to a cascade is exactly where an opt-in quietly becomes a default, and here the failure mode would have been an unattended host waiting on a consent dialog nobody would answer |
| 2026-09-01 | **WSL2 investigated properly — and the recorded blocker was WRONG** | FR-45 recorded WSL2 as having “no ScreenCast backend”. It can have one: **sway (wlroots) + `xdg-desktop-portal-wlr` + PipeWire** puts `org.freedesktop.portal.ScreenCast` on the bus, and the handshake runs all the way to `Start`. ⚠️ The FIRST blocker was simply that **PipeWire was not running at all** (`systemctl --user start pipewire wireplumber`) — the wlr backend refuses to initialise screencast without it and says so |
| 2026-09-01 | **⛔ WSL2 is blocked one layer DEEPER than the FR thought** | `xdg-desktop-portal-wlr`: `unable to receive a valid format from wlr_screencopy`. Cause, from sway's own log: `drmGetDevices2 failed: No such file or directory` — **no `/dev/dri` ⇒ wlroots has no renderer ⇒ screencopy can advertise no buffer format.** Reproduced on the **wayland (nested)** AND **headless** backends, and with the default AND **`WLR_RENDERER=pixman`** software renderers. 🔑 So the same missing `/dev/dri` that blocked FR-36's DRM path also blocks the PORTAL path on WSL2 — the portal was supposed to be the way around it, and it is not |
| 2026-09-01 | **⚠️ And the wlr backend has NO RemoteDesktop at all** | `wlr.portal` declares `Interfaces=…Screenshot;…ScreenCast;` only. Our detector reported it correctly — **the first field exercise of the `remote_desktop=false` branch**: “ScreenCast available but NO RemoteDesktop — capture would be read-only”. ⇒ **P4 cannot be delivered through wlr**, so WSL2 has no portal input path either, on top of having no capture |
| 2026-09-01 | P3b-i validated a second time, for free | The wlr backend logged our `SelectSources` options straight back: `types:1  multiple:0  cursor_mode:2  persist_mode:2` — exactly what we sent. That is a **second, independent implementation parsing the hand-written POD**, on a different compositor stack from the one that validated it first. The error taxonomy held too: `Ended`, not `Cancelled`, because nobody declined — the portal gave up |
| 2026-09-01 | **P4 BUILT — compile+unit-tested, NOT yet field-run** | RemoteDesktop input riding the capture session: arbiter → helper stdin (`InputMsg` JSON lines) → `Notify*`. Unit-locked: HID→evdev via the shared FR-36 table, Unicode keysyms for typed text, logical-size coordinate scaling, wheel detent accumulation, the libinput axis sign, route registration generations. Config keys `portal_capture`/`portal_input` added to the surface (the P3c env `MESHHARBORD_PORTAL_CAPTURE` had NO config key — closed against the standing rule). Pending: the Asahi GNOME field run — dialog wording, devices actually granted, restore-token round trip, scroll SIGN, HiDPI logical-vs-pixel scaling on a 2× panel |
| 2026-09-01 | **P4 field run on scw-m2-asahi (aarch64, GNOME Wayland, RemoteDesktop v2) — PARTIAL, isolated to the consent gate** | Built the P4 branch on the real target (28 s). RemoteDesktop is exposed, `version=2` (persist works), `AvailableDeviceTypes=7` (keyboard+pointer present). **A/B isolation:** capture-only `--stream` RESTORED from the existing token with NO dialog and streamed BGRx 1920x1080 frames (4.96 GB in 20 s) — so the SessionKind/owner-proxy refactor did NOT regress capture; `--stream --input` reached `opening a RemoteDesktop (capture + input) session` and BLOCKED. The one difference is the fresh RemoteDesktop grant with no `-rd` token, so the block IS the one-time GNOME consent dialog — which no one was at the box to approve. ⏳ Injection landing + the restore round-trip stay UNVERIFIED behind that human approval: it is a consent grant ("Allow remote interaction with this device?"), the attended gate this whole FR is built around, and approving it is not an autonomous action. No `-rd` token was written (the run timed out before `Start` returned); the box was left on master, daemon active. ⚠️ The box's SSH host key had changed since the last session — everything else matched (aarch64, m1, the clone, the agent, the GNOME seat0 up since Aug 30), so almost certainly an sshd key regen, but worth a glance. |
| 2026-09-01 | **P4 D-Bus argument shapes PROVEN against the live GNOME RemoteDesktop v2 interface (Asahi), no grant needed** | `busctl introspect` gives every method's exact signature; all six `Notify*` tuples in `input.rs::InputContext::execute` match byte-for-byte: `NotifyPointerMotionAbsolute` `oa{sv}udd` = (session `o`, opts, stream `u`=node_id, x/y `d`); `NotifyPointerButton`/`NotifyKeyboardKeycode`/`NotifyKeyboardKeysym` `oa{sv}iu` = (…, code/sym `i`, state `u`); `NotifyPointerAxis` `oa{sv}dd`; `NotifyPointerAxisDiscrete` `oa{sv}ui` = (…, axis `u`, steps `i`). `SelectDevices` returns `o` (the request handle my `call_with_response` awaits); `AvailableDeviceTypes=7` ⊇ my requested `3` (kbd|pointer). The session is passed as a type-enforced `OwnedObjectPath` (`o`), not a string — the exact P2b object-path-vs-string bug class, correct by construction. So the injection path is now "argument shapes proven against the real interface", not merely "mapping unit-tested"; only the consent-gated LANDING (does the cursor actually move) remains. |
| 2026-09-01 | **Self-review of #1105 (high effort) — 8 findings, 4 correctness ones FIXED before merge** | (1) **zbus-in-tokio panic, live-only**: `InputContext::new` built a `zbus::blocking::Proxy` on the `#[tokio::main]` thread; zbus 5.15's `block_on` does a fresh `Runtime::block_on` ⇒ panics the INSTANT input is granted — the exact hazard `screencast::open` guards against, reintroduced unguarded, and masked in the field run because consent blocked first (the P2b lesson, exactly). Fixed: build the proxy on a joined off-runtime thread. (2) **Capture-coupling regression**: `portal_input` default ON coupled a fresh see+touch consent into every capture and blocked/fell-through if unanswered — overturning the default-ON call. Now default OFF + bounded 120s handshake wait + retry-capture-only on any WithInput failure, so input never costs capture. (3) **Multi-session route overwrite + stuck-modifier**: the single global route slot let a second viewer clobber the first (leaving it input-dead) and stranded held keys; fixed with an ordered append-only registry (oldest-active, hand-off on teardown). (4) **Partial grant**: `& mask != 0` treated keyboard-only as full input; now requires BOTH devices, degrading safely to capture-only. Cleanups: centralised `button_code`, `keysym_of` drops DEL/C1, `call_noreply` for the fire-and-forget `Notify*`. All combos compile; portal+input+core unit tests pass; fmt+clippy `--all-targets -D warnings` clean. |
| 2026-09-01 | **P4 FIELD-VERIFIED end to end on scw-m2-asahi (GNOME Wayland, RemoteDesktop v2)** | Merged #1105, built master on the box (31 s), ran `portal-helper --stream --input`. **Injection LANDS**, measured against DRM capture as ground truth (Xwayland/`xdotool` is NOT usable here — it reported a stale pointer while the captured frame showed the real one): 0.25/0.25 → **(480,270)**, 0.75/0.6 → **(1440,648)**, 0.6/0.2 → **(1152,216)**, all exact. **Scroll sign CONFIRMED as a field fact**: line-mode `dy:+4` scrolled the page DOWN (title → comments) — the libinput convention, so copying evdev's `REL_WHEEL` inversion would have scrolled backwards. **Restore round trip**: a full helper restart came up `input_ok:true` with NO dialog from `portal-restore-token-rd`, and injection landed again. **The D-1 fix is field-proven**: the pre-fix build would have panicked (`Cannot start a runtime from within a runtime`) at the instant input was granted — the helper instead reported `input pump ready` and streamed. |
| 2026-09-01 | ⚠️⚠️ **GNOME puts input behind a SECOND, default-OFF switch inside the same dialog** | The consent dialog is titled **Remote Desktop** and carries `Cancel` / `Share`, a checked **Remember This Selection**, a monitor picker — and an **`Allow Remote Interaction`** toggle that is **OFF by default**. So a human who clicks *Share* without flipping it grants CAPTURE ONLY: `Start` returns `devices` without keyboard/pointer, and the code reports `input_granted=false` → capture-only, exactly the "asked-for is not given" case the review hardened (`& mask == mask`). 🔑 Operator-facing consequence: *enabling `portal_input` is not enough — the person at the screen must also flip that toggle*, and the UI/docs should say so. This is why the partial-grant finding was worth fixing even though GNOME's dialog is "all-or-nothing" for the SHARE decision. |
| 2026-09-01 | **Click + both keyboard paths verified, with a FILE as the evidence** | On the same Asahi session: a portal click focused `gnome-text-editor` and placed the caret; `Key` events (HID→evdev, the shared FR-36 table) typed `abc`; `KeyText` typed ASCII; and **Ctrl+S — LeftCtrl held across `s` — saved the file**, so the proof is 22 bytes on disk rather than a reading of pixels. Zero `input call failed` in the pump. That closes the last untested functional path in P4. |
| 2026-09-01 | 🚨🚨 **`KeyText` is NOT layout-proof — non-keymap characters are dropped SILENTLY by the compositor** | The saved file read `abc Hello FR-45␣␣␣end` where `" Hello FR-45 é € end"` was sent: **`é` and `€` produced NOTHING**, and `NotifyKeyboardKeysym` returned SUCCESS for both — there is no error for our side to see. Corroborated in a second widget: `@ # ~` (shifted levels the US keymap CAN reach) typed fine while `é € £` did not. 🔑 So the rule is **the keysym must exist in the host's ACTIVE keymap**; the compositor synthesises the modifiers for it, but invents nothing. This falsified `input.rs`'s own claim that the keysym path is *"layout-proof … types correctly on layouts the uinput backend refuses"* — the doc is corrected and `run_pump` now warns ONCE when it forwards a non-ASCII keysym (per the standing log-every-silent-drop rule), since "my accented characters vanish" was otherwise unattributable. ⚠️ The real fix is gnome-remote-desktop's: temporarily remap a spare keycode to the wanted keysym — a feature, deliberately NOT attempted here. |
| 2026-09-01 | **⚠️⚠️ CORRECTION — the recorded WSL2 blocker was WRONG IN ITS GENERALITY** | The 09-01 entry above concluded *no `/dev/dri` ⇒ no renderer ⇒ no screencast*. That is true for **wlroots** (it enumerates DRM devices via `drmGetDevices2`, and even `WLR_RENDERER=pixman` could not make `wlr-screencopy` advertise a format) but **false as a general statement about WSL2**. Measured: `LIBGL_ALWAYS_SOFTWARE=1` gives **llvmpipe, OpenGL 4.5 core, on the Wayland AND surfaceless EGL platforms, with no `/dev/dri` at all** (`d3d12_dri.so` is present but unusable — Mesa reports `failed to get driver name for fd -1` because there is no DRM node). So a compositor that renders through EGL has a path where wlroots does not. |
| 2026-09-01 | 🏆 **`mutter --headless` RUNS in WSL2 and exposes a screencast API** | `mutter --headless --wayland --virtual-monitor 1920x1080` with software EGL: `Created surfaceless renderer without GPU`, `Added virtual monitor Meta-0`, `Using Wayland display name 'wayland-1'` — a real compositor with a real 1920×1080 output on the host FR-45 was opened for. It exposes **`org.gnome.Mutter.ScreenCast` v4 and `org.gnome.Mutter.RemoteDesktop` v1**, and with the GNOME portal backend up our own detector reported **`available (screencast v5, remote_desktop=true)` in WSL2**. |
| 2026-09-01 | ⛔ **…but the PORTAL path still cannot complete there — for a DIFFERENT reason, higher up the stack** | `xdg-desktop-portal-gnome` **exits immediately** without a real GNOME session (its only log line is `Failed to associate portal window with parent window`), so it never owns `org.freedesktop.impl.portal.desktop.gnome`; the frontend then D-Bus-activates it and times out, and our client reports it exactly: `CreateSession: … StartServiceByName for org.freedesktop.impl.portal.desktop.gnome: Timeout was reached`. ⚠️ Note the P1 lesson recurring: the frontend ADVERTISED ScreenCast+RemoteDesktop the whole time (backends declare interfaces in `.portal` files), so "the interface is exposed" again proved nothing. ⚠️ And a full nested GNOME is not the way out: `mutter --nested` HANGS before creating its socket — WSLg's compositor offers only `xdg_wm_base` v1 / `wl_compositor` v4 and **no `zwp_linux_dmabuf_v1`** (that protocol gap is the likely cause — inferred, not proven). |
| 2026-09-01 | 🔑 **The identified path forward for WSL2 (NOT attempted)** | Talk to **`org.gnome.Mutter.ScreenCast` directly**, which is what gnome-remote-desktop does — it needs no portal backend and no consent dialog, both of which are what actually block WSL2. That is a new, GNOME-specific code path, so it is a phase, not a tweak. ⚠️ It could not be probed with `busctl`: a mutter screencast session dies with the D-Bus connection that created it (the same rule our own `Session::_conn` field exists for), so per-call shell tools cannot hold one open — proving it needs code. |
| 2026-09-01 | ✅ **P5 field-verified on Asahi (real GNOME)** | `portal-helper --stream --mutter`: **`mutter node 82 on HDMI-1 (ScreenCast v4)` in 10 ms, NO consent dialog**, BGRx 1920×1080 negotiated. Frames are **damage-driven**: 85 bytes (the handshake alone) while the desktop sat idle, then **904 MB** once the pointer was swept across it. |
| 2026-09-01 | 🏆🏆 **P5 PAYOFF — a Wayland desktop is CAPTURED IN WSL2, the host this FR was opened for** | Headless mutter (`Created surfaceless renderer without GPU` / `Added virtual monitor Meta-0`), **no portal backend owning a name on the bus at all** — so the portal path provably could not have served this — and `portal-helper --stream --mutter` gave **node 32 on `Meta-0`, ScreenCast v4, open in 28 ms**, BGRx 1920×1080. 85 bytes idle → **4.92 GB** once a client mapped. Pixels checked to the P3c-i standard: magic `RPWF`, stride 7680 = 1920×4, len 8294400 = a full frame, **2025/2025 sampled bytes non-zero**, and **frame 2 ≠ frame 1** — live pixels, not a still and not black. |
| 2026-09-01 | ⚠️ **A unit test at the WRONG LEVEL passed while the code was broken** | The first `mutter.rs` test pinned `MonitorEntry`'s signature — correct — while `first_connector` deserialised `GetCurrentState`'s reply as a **2-tuple**, and the real reply has **four** fields. Every live call failed `Signature mismatch: got (ua(…)a(…)a{sv}), expected (ua(…))`. 🔑 zvariant matches the WHOLE body: reading "just the fields we want" is a type error, not a partial read. The test now pins the entire reply signature. A test at the wrong level is worse than none — it reports the shape as locked while the shape that actually broke was never looked at. |
| 2026-09-01 | ⚠️ **clippy caught a bound that did not bind** | The first draft wrapped the `PipeWireStreamAdded` wait in a `loop` with a deadline check — but every arm broke or returned on the first pass, so `STREAM_WAIT` was dead code and the wait was actually UNBOUNDED (`this loop never actually loops`). zbus's blocking signal iterator has no timed `next`, so the bound now wraps the whole handshake in [`open`] via a thread + `recv_timeout`, the same shape `pipewire::negotiate` already uses. |
| 2026-09-25 | **AC2 — the BEFORE state, 0.4.101 (= master), WSL2** | The deploy as found captures through the **Xvfb virtual desktop**: `capture: backend=scrap (DXGI/XShm/CoreGraphics) 1920x1080` + `X11 damage tracking active`. Its last session (2026-09-24, same build): `codec_label="HEVC" encoder="hevc_nvenc"` 1920×1080, **`avg_encode_ms` 9.8 → 11.9** across 274 heartbeats (~9 min), `constrained=true`, `frames_captured` 2 → 674. The caps probe on this build: `hw_encoders=["openh264-sw", "ffmpeg-hevc_nvenc", "ffmpeg-av1_nvenc", "ffmpeg-h264_nvenc", "libvpx-vp9-444-sw"]` on an RTX 5090 laptop GPU (driver 610.88), `/dev/dxg` present, `/dev/dri` still absent. **No session on the P5 path had ever been encoded** — the 09-01 verification stopped at pixels. |
| 2026-09-25 | ⛔ **P5 is UNREACHABLE THROUGH THE DAEMON on WSL2 as shipped — the control run** | Flags on (`MESHHARBORD_PORTAL_CAPTURE=1 MESHHARBORD_MUTTER_CAPTURE=1`, virtual desktop off), mutter not running, `capture-smoke` as root — i.e. the daemon's own `open_default`: `portal capture: using org.gnome.Mutter.ScreenCast DIRECTLY …` and then **`MESHHARBORD_PORTAL_CAPTURE=1 but portal capture could not open — falling through to the standard cascade error=nobody is at this machine's screen — the portal is attended-only`**. Cause: `helper::spawn_child` resolves the session user with `companion::graphical_session()`, which accepts only a logind session of `Type=x11`/`wayland` with `Active=yes`; a WSL2 distro has only `Type=tty` sessions (`loginctl`: two `pts` sessions, `seat0` empty). 🔑 **The 09-01 P5 run drove `portal-helper --stream --mutter` BY HAND as the user**, so this lookup was never exercised — the by-hand helper masked the gap. Neither mutter nor the `--mutter` helper needs a logind session; only the daemon's lookup does. |
| 2026-09-25 | 🔑 **What makes the daemon path work on WSL2: give logind a wayland session** | `pam_systemd` reads `XDG_SESSION_TYPE` from the *unit's* environment (`getenv_harder`), so a transient unit with `PAMName=login` registers exactly the session the daemon's lookup wants — seatless, hence `Active=yes` — and can run the compositor at the same time: `systemd-run --unit=fr45-mutter -p User=<user> -p PAMName=login -p Environment=XDG_SESSION_TYPE=wayland -p Environment=XDG_SESSION_CLASS=user -p Environment=XDG_RUNTIME_DIR=/run/user/<uid> -p Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/<uid>/bus -p Environment=LIBGL_ALWAYS_SOFTWARE=1 /usr/bin/mutter --headless --wayland --no-x11 --wayland-display wayland-fr45 --virtual-monitor 1920x1080`. Result: `loginctl` gains a `Type=wayland Class=user Active=yes` session for the user, and `busctl --user list` shows mutter owning `org.gnome.Mutter.ScreenCast`, `DisplayConfig`, `RemoteDesktop` and `InputCapture` on `/run/user/<uid>/bus` (PipeWire 1.0.5 already running under `user@<uid>`). Daemon side: a drop-in with `MESHHARBORD_VIRTUAL_DESKTOP=0`, `MESHHARBORD_PORTAL_CAPTURE=1`, `MESHHARBORD_MUTTER_CAPTURE=1` — the virtual desktop OFF on purpose, so the scrap/X11 fallback cannot quietly serve the session in the portal's place. Motion on the virtual monitor: `weston-simple-egl -f` + `weston-simple-shm` as the user with `WAYLAND_DISPLAY=wayland-fr45` and `LIBGL_ALWAYS_SOFTWARE=1`. ⚠️ `PAMName=login` logs `PAM unable to dlopen(pam_lastlog.so)` on Ubuntu 24.04 — harmless, the module is `optional`. |
| 2026-09-25 | 🏆 **P5 engages THROUGH THE DAEMON'S CASCADE on WSL2, with frames — 0.4.101** | Same `capture-smoke` as root with the rig above up: `portal-helper: opening an org.gnome.Mutter.ScreenCast session (UNATTENDED)` → **`mutter node 44 on Meta-0 (ScreenCast v4, 22 ms)`** → `streaming 1920x1080 (spa format 8)` → `capture: backend=portal … width=1920 height=1080` → **`delivered=30 empty=0 unchanged=0 monitors=1 1920x1080 stride=7680 format=Bgra mean_ms=18.46 worst_ms=35.88`**. The dumped PPM is a correct picture — the `weston-simple-egl` RGB triangle, right geometry and colours, on black — and `unchanged=0` across all 30 frames is live motion. ⚠️ **With nothing drawing, the identical run reported `30 attempts, 30 empty, ZERO frames delivered`**: mutter's screencast is damage-driven, and an idle virtual monitor produces nothing at all, which reads exactly like a broken capture. Put a client on the monitor before believing "no frames". |
| 2026-09-25 | ⏳ **AC2's encode half — NOT read, and why** | The measurement needs a live remote-desktop session: the pump's `DC pump heartbeat` is what carries `encoder=` and `avg_encode_ms`, and nothing offline measures it (`encoder-smoke` proves an open and an IDR, not a per-frame cost). The controller available to the run — the Claude-in-Chrome profile on the dev box — was **signed out** of roomler.ai (`/tenant/…/devices` bounced to `/login`), and a worker may not enter credentials, so the run stopped there rather than fake the half. Left to do, ~10 min: bring the rig above up, sign in, open the device's viewer for ≥2 min while the weston clients animate, and read `journalctl -u roomlerd \| grep 'DC pump heartbeat'` — pass if `encoder="*_nvenc"` and the mean `avg_encode_ms` ≤ ~21 (2× 10.4). The host was restored after the run: drop-in removed, transient units stopped, Xvfb virtual desktop back. |
| 2026-09-25 | 🏆 **AC2 encode half READ — resumed once the browser was signed in, 0.4.101, WSL2** | Same P5 rig (PAM-registered wayland session + headless mutter + weston motion, daemon drop-in `VD=0`/`PORTAL_CAPTURE=1`/`MUTTER_CAPTURE=1`), a live RC session opened from the signed-in controller. The daemon took the P5 path — `portal capture: using org.gnome.Mutter.ScreenCast DIRECTLY` → `mutter node 44 on Meta-0 (ScreenCast v4)` → `media pump: AV1 over DataChannel` — with the virtual desktop OFF, so no Xvfb fallback. **Encoder = `av1_nvenc`; `avg_encode_ms` mean 8.25 ms** (min 5.69, max 12.70) across **68 `DC pump heartbeat`s / 6 sessions**, `c=true` (relay). Within ~2× of the 10.4 ms baseline — below it, in fact. ⚠️ **All at 1280×720, not the baseline's 1920×1080**: the relay pair is remembered slow-link (FR-59 `remembered_bps≈26592`), so the pump opens capped `max_long_edge=1280 max_fps=15` and does not climb. A smaller frame encodes faster, so this is **not** a like-for-like reproduction of the 1080p number — AC2 is `[~]`, not `[x]`. ⚠️ Sessions were short (~30 s each): the automation tab is `visibilityState:hidden`, so the viewer's decode-progress watchdog (`useRemoteControl.ts` — media-progress ticks drive it) re-creates the session; the agent-side heartbeats are valid regardless, but no single 2-min session accrued. |
| 2026-09-25 | ⛔ **The 1080p arm is blocked on this host — and the wrong turn is worth recording** | To lift the 720p cap I set `MESHHARBORD_SLOW_LINK_PROFILE=0`. That is a `MESHHARBORD_*` knob, and the caps cache is keyed on the knob set, so it forced a **fresh caps probe** — which **hung** under the daemon's minimal systemd environment while the test rig loaded the box (`caps probe: the probe child hung`; `env -i roomlerd caps` reproduces a 75 s hang, while an interactive `caps` with the login env completes in ~5 s). The 94 s pump watchdog then `exit(2)`-looped the daemon (`watchdog: pumps stalled … forcing exit(2)`, `crash_count` climbing). 🔑 Pre-warming the single-entry cache with a matching key did **not** hold — the daemon recomputed a miss — so the knob is not safely settable on this host under load. Recovery: stop the transient units (frees the GPU), remove the drop-in, restart on the original config — the **fresh probe then completed in 4.6 s with the GPU idle** and the daemon came up `rc:agent.hello sent`, peers online. So the 1080p read is blocked by **two** independent things — slow-link rate memory forcing 720p, and a fresh-probe hang under load — neither in the P5 capture path itself. (The probe-under-load hang looks like its own latent WSL/NVENC issue, not an FR-45 defect.) |
| 2026-09-25 | **AC2 1080p arm — the BEFORE, 0.4.102, WSL2** | Two befores stand on record for this arm: the deploy as found (Xvfb virtual desktop, `hevc_nvenc`, 1080p, 9.8–11.9 ms — the row above) and the same day's P5 sessions at **1280×720**. The cap's mechanism, read off the host: `rate_memory.json` held ONE bare-address entry for the relay address at **43 514 bps** (the 720p run had seen ≈26 592), and any remembered rate ≤ 1 Mbps opens a constrained pump at `max_long_edge=1280 max_fps=15` (`rate_profile.rs:413`). ⚠️ That memory reads as **self-inflicted by the test rig** rather than a property of the link: the day's sessions were ~30 s each in a hidden automation tab, and what a session measures is what it writes back, so each short session made the next one open smaller. A hypothesis from the numbers, not an A/B — recorded so the next reader does not treat "this pair is slow" as a fact. |
| 2026-09-25 | **The knob change, sequenced around the probe landmine** | The box was shared with two other workers' `cargo` jobs (load 15–28 on 32 cores), so a bounded wait fired the change the moment no builder process remained (load 5.5): drop-in `MESHHARBORD_VIRTUAL_DESKTOP=0` / `PORTAL_CAPTURE=1` / `MUTTER_CAPTURE=1` / **`SLOW_LINK_PROFILE=0`** as ONE knob change, the rate-memory entry cleared (a backup kept on the host), `daemon-reload`, restart. The fresh probe (`cache miss … reason=a MESHHARBORD_* knob changed`) completed in **10.4 s** (4.6 s at idle the same morning; 60 s is the bound), `rc:agent.hello sent` 13 s after `agent starting`, `NRestarts=0`, no Xvfb, peers online — and only then the rig: `systemd-run` mutter with `PAMName=login` + `XDG_SESSION_TYPE=wayland` (logind gained a `Type=wayland Class=user Active=yes` session), `weston-simple-shm` + `weston-simple-egl -f` on its display. 🔑 Both levers were pulled on purpose — the knob AND the cleared memory: the 10.4 ms baseline (0.4.33, 2026-08-31) predates FR-59 P5 (2026-09-01), so "profile off, no memory" IS the baseline's condition, and pulling one alone risked a second knob restart under load if the other still capped the open. |
| 2026-09-25 | 🏆 **AC2 MET like for like — 1080p on the P5 path, 0.4.102, WSL2** | Viewer opened from the signed-in controller; its `rc:resolution` default is `original` and no preference was stored for this device, so the request does not depend on the viewport and the hidden tab is not a resolution confound (checked in `localStorage` before connecting). Every session took the same path: `portal capture: using org.gnome.Mutter.ScreenCast DIRECTLY` → `portal-helper: mutter node 44 on Meta-0 (ScreenCast v4, 16–60 ms)` → `streaming 1920x1080` → `capture: backend=portal … width=1920 height=1080` → `ffmpeg encoder opened … encoder="av1_nvenc" width=1920 height=1080 fps=30`; no slow-link line. **109 `DC pump heartbeat`s across 5 sessions, all `1920x1080`, `encoder="av1_nvenc"`, `avg_encode_ms` mean 11.39 (min 6.24, max 16.73)**; per session 7.06 (n=3), 8.69 (n=4), 8.86 (n=5), **12.00 (n=30, ~60 s)**, **11.66 (n=67, ~2.2 min, 6 484 frames captured)** — the short sessions' means are dominated by the opening frames, so the sustained figure is ~11.7–12 ms: **1.1–1.15× the 10.4 ms baseline**, `target_fps=30`, `constrained=true` (relay), `target_bps` 2.7–3.2 M. The viewer's HUD agreed: `1920×1080 shown at 1.08× ~45 ms`, `AV1 4:2:0 HW (av1_nvenc) · relay · dec HW`. ⚠️ The hidden tab's decode-progress watchdog still re-created sessions (`Connection lost — reconnecting … Reconnected in 1.8 s after 1 failed`), though two ran a full minute; the agent-side heartbeats are valid regardless. |
| 2026-09-25 | Two log lines on this path that are noise today and worth a look | (1) `FFmpeg DC pump: encoder ignored forced keyframe — rebuilding to emit a guaranteed IDR (vp9_qsv-class runtime-force bug)` fired once per session ~14 s in, on **`av1_nvenc`** — the handling covers it (a sub-second rebuild and a fresh IDR), but NVENC ignoring a forced keyframe is not the case the message was written for; encoder-side, not FR-45's. (2) `portal capture: frame stream ended error=failed to fill whole buffer` at WARN on **every** normal session teardown — the reader hits EOF mid-frame when the helper is killed with the capture; harmless, but a WARN that fires on every clean stop should become a debug line when the capture is being dropped (`portal/backend.rs`). |
| 2026-09-25 | ✅ **Host restored and verified** | In the order the landmine dictates: the rig down FIRST (`fr45-*` units stopped, none left), then a bounded wait for the shared host to have no builder running (fired at load 3.9), then the drop-in removed, `daemon-reload`, restart. The second fresh probe of the run (`cache miss … a MESHHARBORD_* knob changed` — restoring the old knob set misses the single-entry cache too) completed in **6.6 s**, `rc:agent.hello sent` for both orgs, `NRestarts=0`; Xvfb `:103` back with xfwm4 and the two startup apps; only the three standing drop-ins; no leftover mutter/weston/`portal-helper`; logind back to its two `tty` sessions; peers online. The daemon's own write-back to `rate_memory.json` after the run: **3 187 500 bps** for the relay it nominated — a healthy number where the morning's entry held 43 514 (⚠️ a different relay address was nominated this time, so this is not a same-key A/B; the artefact's key is simply gone, and the pair opens with no memory next time). |
