# FR-41: A 90-second demo of the product actually working

> **CLOSED 2026-09-01** — issue #965 is closed and its acceptance criteria are met. Any status line below is the state while the work was in flight, kept as the record.

Status: **P0 in progress** (2026-08-30). Tracking issue: `FR-41` (#965).
Child of FR-39 (#951), which shipped everything else in launch phase 0 and left this
as the one asset nobody else can substitute for.

## Why this is the blocking asset

FR-39 made the product *findable*: the repository description leads with remote desktop
and WireGuard mesh, twenty discovery topics are live, five comparison documents exist, and
there is a one-command self-host path. What none of that does is **show the product
running**. Every downstream channel reuses the same artifact — the README's first screen,
a Reddit release post, a Hacker News thread, a Product Hunt listing, the first newsletter —
and a still image cannot carry "your machine's desktop, in a browser tab, in ten seconds".

⚠️ The existing `roomler-intro.mp4` is a **collaboration walkthrough** (2:24). It predates
the three-pillar pivot in #490 and shows the pillar that is now third. Linking it from a
launch is worse than linking nothing: it confirms the stale positioning that a web search
for the product still returns.

## Goal

One take, **≤ 90 seconds**, no narration, showing a machine being enrolled and then
reached four ways: its desktop in a browser tab, a shell with no `sshd`, a forwarded port,
and its address on the mesh. Reproducible from a script, so it can be re-recorded when the
UI changes rather than becoming a fossil.

## Staging — decided 2026-08-30

| | |
|---|---|
| **Controller** | neo16's browser, driven by Playwright |
| **Target** | the **WSL2 Ubuntu 24.04 sibling** on neo16, enrolled into a fresh `demo` org |
| **Server** | production `roomler.ai` |

⚠️ **Why not neo16 itself.** Two reasons, and the second is fatal to the footage:
1. Removing neo16 from GROX is **irreversible** — agents are tombstoned, and a re-enrolled
   machine gets a fresh lease, never its old `100.65.4.2` back. It would also drop neo16
   off the mesh the operator reaches the fleet through.
2. A browser on neo16 remote-controlling neo16 is an **infinite mirror** in the one scene
   the whole video exists for.

The WSL sibling is a genuinely separate machine identity (it already runs its own
`roomlerd`), it is disposable, and the enrolment on camera is real rather than staged.

## Key design

1. **Reuse the existing harness, don't build one.** `ui/e2e/video/record-intro.spec.ts` +
   `playwright.video.config.ts` + `scripts/record-video.sh` already record a browser
   journey to WebM, inject an on-screen caption overlay per scene, and convert to MP4 with
   optional music. It already supports production mode via `E2E_USERNAME` /
   `E2E_PASSWORD` / `E2E_TENANT_ID`. A new `record-demo.spec.ts` sits beside it.
   ⚠️ `ui/e2e/video/` uses bun-only JSON-import syntax (`with { type: 'json' }`) and kills
   Playwright's collection under plain node — which is why the nightly e2e lane copies
   `ui/` *minus* that directory. Record with bun, or convert the import.
2. **Scene list, budgeted to 90 s.** Each scene is a caption plus the real UI:

   | t | scene | shows |
   |---|---|---|
   | 0–6 s | the org, empty | one machine about to exist |
   | 6–22 s | Devices → Enroll → token → the one-line installer → the device appears **online** | that enrolment is one command |
   | 22–48 s | open its desktop in the browser, move around | the headline claim, unfaked |
   | 48–62 s | Network view — mesh graph, stable address, MagicDNS name | it is a network, not a screen-sharing tool |
   | 62–82 s | a shell and a forwarded port | reach the machine's *services*, not just its screen |
   | 82–90 s | end card | where to get it |

3. **The command scenes stay in the browser.** `roomler ssh` and `roomler forward` are
   terminal commands, and compositing a separate terminal capture into a browser recording
   is where this kind of project stalls. The device console in `DevicesView.vue` runs
   commands *in the page*, so the recording stays one continuous browser take.
4. **The target needs something to look at.** A blank WSLg desktop is not a demo. The
   pre-flight script launches a small, real workload on `DISPLAY=:0` before recording.

## Phases

| phase | scope | kill switch |
|---|---|---|
| P0 | `demo` org on prod + WSL sibling enrolled into it + desktop made presentable | delete the org; the sibling's GROX membership is untouched |
| P1 | `record-demo.spec.ts` + scene captions + a `scripts/record-demo.sh` wrapper | additive files only |
| P2 | record, convert, trim to ≤90 s, embed in the README | revert the README hunk |
| P3 | re-record when the UI changes — the point of scripting it | — |

## Acceptance criteria

- [ ] the recording is **≤ 90 s** and has no narration
- [ ] it shows a real enrolment that transitions a device to **online** on camera
- [ ] it shows the target's actual desktop in a browser tab, with input working
- [ ] it shows a shell and a forwarded port
- [ ] `scripts/record-demo.sh` reproduces it end to end from a clean `demo` org
- [ ] it is embedded at the top of the README, above the pillar sections
- [ ] neo16's GROX membership and `100.65.4.2` are **unchanged** afterwards

## Open decisions

- **Music.** The existing harness can mix a track. A silent demo is safer for embedding in
  a Reddit post; music helps on a landing page. Cheap to add later, so P2 ships silent.
- **Where the file lives.** A 10 MB MP4 in the repository is what `roomler-intro.mp4`
  already does. A GIF is smaller and auto-plays in a README but looks far worse for a
  screen recording. Likely both: GIF in the README, MP4 linked.

## Out of scope

Re-recording the collaboration walkthrough · marketing voiceover · localised captions ·
anything that requires removing neo16 from GROX.

## Field-verification log

| date | what was checked | result |
|---|---|---|
| 2026-08-30 | neo16 agent state before any change | `0.4.21`, service (SYSTEM), tenant `69a1dbba…`, overlay `100.65.4.2`, MagicDNS `grox.roomler.ai`, server connected — the baseline this FR must not disturb |
| 2026-08-30 | WSL2 sibling is a usable target | Ubuntu 24.04.4, own `roomlerd` running, 45 GB RAM / 272 GB free, `DISPLAY=:0` via WSLg (no Xvfb needed) |
| 2026-08-30 | existing harness supports production | `record-intro.spec.ts` reads `E2E_USERNAME` / `E2E_PASSWORD` / `E2E_TENANT_ID` |
| 2026-08-30 | **P0: the sibling joined `demo` as a SECONDARY org — GROX intact** | `roomlerd enroll --label demo` against a token for a new org on the SAME server **appends** rather than replaces (the flag's documented behaviour, confirmed live): the WSL sibling is online in `demo` AND still online in GROX under its original name. Option B therefore cost nothing — the irreversible-removal risk this FR was staged around does not apply when the target is a second org on one server |
| 2026-08-30 | agent capability is not the problem | `wsl-demo` advertises `permissions: [screen-capture, input]`, NVENC + openh264 + libvpx encoders, `multi_org: [join, tun]`, and rpc `exec` / `ssh` / `config` |
| 2026-08-30 | ⚠️ **a session CONNECTS and negotiates a codec while delivering ZERO frames** | Connect reached `connected · VP9 4:4:4` with `— bps — fps`, `<video>` 0×0/paused and an unpainted 300×150 canvas. Cause: the agent is a **root systemd service with no `DISPLAY`** and there was no Xvfb, so X11 capture had nothing to open. ⚠️ Worth surfacing beyond this FR: a headless Linux agent reports FULL `screen-capture` capability and completes signalling, so at the viewer the failure is indistinguishable from a slow link. Same shape as the FR-34 (#917) stuck-capture class |
| 2026-08-30 | ⚠️⚠️ **virtual-desktop startup apps WEDGE the systemd unit** | `MESHHARBORD_VIRTUAL_DESKTOP=1` with `STARTUP=xterm,pcmanfm` left the unit in `deactivating (stop-sigterm)`: `roomlerd` exited 0, but a **grandchild** — `/usr/libexec/at-spi-bus-launcher`, spawned by the GTK file manager — outlived it and held the cgroup open, so systemd could not finish stopping and never started the replacement. **The daemon was DOWN** until the stop timeout reaped it. A startup app that forks an accessibility or D-Bus helper is entirely ordinary, so this is not exotic: it wants `KillMode`/cgroup handling on the unit, or a virtual-desktop teardown that reaps its own descendants |
| 2026-08-30 | the wedge cleared itself | systemd's stop timeout reaped the stray after **50 s** and started the replacement. So it self-heals — but the daemon is offline for the whole window, and nothing in the logs says why |
| 2026-08-30 | ✅ **the remote-desktop scene is PROVEN end to end** | With `MESHHARBORD_VIRTUAL_DESKTOP=1`: Xvfb `:100` at 1920×1080, openbox, xterm and pcmanfm. The session streams **`H.265 4:2:0 HW (hevc_nvenc)` at 15 fps, 1920×1088, ~41 ms** over a relay carrier, canvas painting at 2026×1148. ⚠️ `<video>` stays 0×0/paused — that is the WebCodecs canvas path working, **not** a fault; judge the canvas dimensions instead |
| 2026-08-30 | ✅ **input injection works** | Clicked into the remote xterm from the browser and typed `htop`; it ran on the WSL machine, and the bitrate rose **27 → 116 kbps** from the live redraw — which also proves the stream is live rather than a still. The FR-27 viewer-presence badge (`GJ`) renders on the remote desktop |
| 2026-08-30 | ❌ **Wayland is not an option, and it is not a config problem** | Asked whether WSLg's Wayland could give a nicer desktop. It cannot: the agent has **no Wayland capture backend at all** — `capture/` holds `scrap_backend` + `x11_damage` (X11), `wgc_backend` (Windows) and `synthetic_backend`, and nothing referencing wayland/pipewire/portal. FR-36 (#929) has it at *design*. Pointing the agent at Wayland would turn a working stream black, and WSLg's compositor is a **per-user session service** against a root daemon — which is FR-36's unsolved P0, not an incidental setting |
| 2026-08-30 | ⚠️⚠️ **WSLg's Wayland actively breaks X11 GUI apps unless the backend is pinned** | GTK **prefers Wayland whenever `WAYLAND_DISPLAY` is set**, and WSLg sets it in every environment. So apps launched with `DISPLAY=:100` still tried to reach WSLg's compositor and died with `libwnck ... no valid display found` — i.e. they targeted the wrong display entirely while looking like an app crash. `unset WAYLAND_DISPLAY` + `GDK_BACKEND=x11` is the fix, and it is why any WSL capture work needs it |
| 2026-08-30 | ⚠️ **do not swap the WM under a live capture** | `xfwm4 --replace` against the Xvfb the agent was capturing **wedged the X server**: `xwd` and `xwininfo` stopped answering and the desktop had to be rebuilt. openbox (what the daemon starts) works with capture; dress around it rather than replacing it. `xfce4-panel`/`xfdesktop` are separately unusable here — both need a session manager that does not exist (`Failed to connect to the session manager`) |
| 2026-08-30 | ⚠️ **the virtual desktop walks its display number and leaks lock files** | Each daemon start takes the next FREE display, so a few restarts moved it `:100 → :101 → :102` while leaving `/tmp/.X100-lock` and `/tmp/.X101-lock` behind. Anything that hardcodes `:100` silently talks to a dead server — `scripts/demo-desktop.sh` discovers it from `pgrep Xvfb` instead |
| 2026-08-30 | ✅ **dressed desktop verified through a real session** | Teal gradient wallpaper, htop across 32 cores in a styled terminal, Thunar with icons — streaming `H.265 4:2:0 HW (hevc_nvenc)`, 15 fps, 1920×1088, ~46 ms. Reproducible via `scripts/demo-desktop.sh`. htop earns its place twice: it fills the frame with real system state, and its redraw proves to a viewer that the stream is live rather than a still |
