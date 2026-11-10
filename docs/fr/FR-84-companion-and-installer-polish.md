# FR-84: The companion and the installer, finished — it starts after install, explains itself, and its pages hold still

**Issue:** [#1633](https://github.com/jk-zhang-meta/MeshHarbor/issues/1633) · **Status:** **closed 2026-09-26 — all 14 criteria field-verified** — shipped in 0.4.103; field fixes #1682 + #1688 in 0.4.104 and #1703 in 0.4.105 ·
**Related:** [#1631](https://github.com/jk-zhang-meta/MeshHarbor/issues/1631) (web: RC view stuck on the previous device) ·
[#1632](https://github.com/jk-zhang-meta/MeshHarbor/issues/1632) (a terminated session leaves the consent prompt up) ·
[#1035](https://github.com/jk-zhang-meta/MeshHarbor/issues/1035) (a route port held by a companion the daemon spawned) ·
FR-11 (server-side grids) · FR-27 (consent surfaces) · FR-61 (vmtest)

## Goal

**Installing MeshHarbor ends with the companion open in front of the person who installed it,
saying what the device can do and asking the one question that matters — turn on the private
network? — and every companion page shows something a person can read and act on.**

The operator's report (2026-09-25) listed nine items across `meshharbor-desktop`,
`meshharbor-setup` and the web app. The two web-side defects are one-PR bugs and are tracked
alone (#1631, #1632). This FR carries the rest, because they share one surface — the
companion and the LocalAPI it stands on — and one acceptance bar: a person who never read
the docs can install, understand and operate the device.

## The field evidence

Measured on the reporting host (Windows 11, perMachine install, daemon 0.4.101, worker in
user context, seven declared routes) and on production, 2026-09-25.

### The Routes page: the data holds still, the pipe does not

The page's "Declared routes" and "Live forwards" appear and disappear every few seconds. The
daemon's own answers do not change:

```
6 samples of `mh route ls` + `mh flows` over 10 s:
  7 routes, every one `active`, the same flow ids (fl-1 … fl-48) every time
24 concurrent `mh route ls` (8 at a time): 24/24 rc=0
```

The named pipe does. Three back-to-back raw `CreateFileW` opens of `\\.\pipe\meshharbor` —
exactly what the Rust client does — repeated 60 times, 100 ms apart:

```
open1=ok       60
open2=err231   60      ← ERROR_PIPE_BUSY
open3=err231   59
open3=ok        1
```

⚠️ A .NET `NamedPipeClientStream.Connect(0)` probe of the same thing reported 90/90 OK: it
calls `WaitNamedPipe` first, and `0` there means *the server's default wait* (50 ms). A probe
that waits cannot see a gap the Rust client does not wait through.

### The setup download

```
curl -sI https://meshharbor.itachi.fans/api/setup/windows → meshharbor-setup-0.4.48-x86_64-pc-windows-msvc.zip
curl -sI https://meshharbor.itachi.fans/api/setup/linux   → meshharbor-setup-0.4.48-x86_64-unknown-linux-gnu.tar.gz
curl -sI https://meshharbor.itachi.fans/api/setup/macos   → 404
/api/setup/latest-release                     → exactly one release: setup-v0.4.48 (2026-09-02)
```

The agent lane is at `agent-v0.4.102`. The resolver is correct — it serves the newest
`setup-v*` that exists (`crates/modules/fleet/src/setup_release.rs:418-439`); nothing has
cut one since 0.4.48, which shipped without macOS (`skip_macos`, before Apple signing).

## The mechanism, in the code (master `4b7b28537`)

*Every anchor in this table resolves at `4b7b28537`, and stays there: the table records the code before FR-84 changed
it. Do not shift these anchors with code that moved later.*

| Surface | Where | What it does today |
|---|---|---|
| Routes poll | `agents/meshharbor-desktop/src/front/tunnels.js:285`, `app.js:166-168` | two 2 s intervals armed at load: device view (1 connection) + routes + flows (2 more) |
| swallowed errors | `agents/meshharbor-desktop/src/commands.rs:1007-1011`, `:1052-1057` | `Err(_) => Vec::new()` — any failure renders as "no routes" |
| empty paint | `tunnels.js:126-129`, `:176-179` | `paintRoutes([])` hides the table; `paintFlows([])` hides the card |
| pipe server | `crates/localapi/src/lib.rs:1796-1871` | ONE listening instance; the next is created only after `connect()` returns |
| pipe client | `crates/localapi/src/lib.rs:2133-2153` | retries `ERROR_PIPE_BUSY` once, after 50 ms |
| settings list | `crates/agent-core/src/config_surface.rs:42-836` | 150 `(key, kind, description)` tuples, no grouping; `restart_required` hard-coded `true` (`:21, :827, :841`) |
| live keys | `agents/meshharbor-desktop/src/front/settings.js:60-63` | a hand-kept `LIVE_KEYS` list the daemon does not know about |
| restart | — | nothing in the desktop or on the LocalAPI can restart the daemon |
| encoder caps | `agents/meshharbord/src/encode/caps.rs:37, 548-559` | a process OnceLock filled at the first `rc:agent.hello`; never on the LocalAPI |
| drop folder | `agents/meshharbord/src/files.rs:1966-2030` | SystemContext → the active user's Downloads; else the process owner's; Windows fallback `%PROGRAMDATA%\meshharbor\<segment>\uploads`; not configurable |
| devices | `agents/meshharbor-desktop/src/front/devices.js:58, 179` | LocalAPI `Peers` (netmap) every 2 s, `p.name` only, no `display_name`, orgs mixed |
| agent-token routes | `crates/modules/fleet/src/lib.rs:331-340` | crash / self-unenroll / logs; nothing lists devices; the web grid and mesh are `AuthUser` |
| launch after install | `scripts/install.ps1:283-305`; `agents/meshharbor-setup/src/orchestrator_agent.rs:501-610`; `agents/meshharbord/wix*/main.wxs` | copy the EXE, launch nothing, register nothing |
| first launch | `agents/meshharbor-desktop/src/main.rs:57-75`; `tauri.conf.json:26` | `--view=` handled only in the single-instance callback; the window starts hidden |
| companion spawn | `agents/meshharbord/src/companion.rs:689` | `std::process::Command` (inherits handles) on the user-session path; the SYSTEM path already passes `bInheritHandles = FALSE` |
| wizard release | `.github/workflows/release-setup.yml` | runs only on a `setup-v*` tag or a manual dispatch |
| wizard icon | `agents/meshharbor-setup/icons/` | 72-byte `.ico` / 67-byte `.png`, 1×1, since `540e056a4` |
| overlay default | `agents/meshharbor-setup/src/front/index.html:120-131` | `#adv-overlay` unchecked for every role |

## Key design

Decisions taken with the operator on 2026-09-25: the desktop lists the devices **this
device's netmap already carries**, not the org inventory; the wizard releases in
**lockstep** with the agent; "Apply now" is a **daemon self-restart under a detected
supervisor**; the wizard icon is a white R on **green `#2E7D32`**.

### S1 — the wizard ships in lockstep

`release-agent.yml` gains `dispatch-setup-release` (after `release`, `if: is_release`,
skippable with the repo variable `SETUP_LOCKSTEP=false`): it tags `setup-v<V>` at the agent
commit — a `GITHUB_TOKEN` push triggers no workflow, by design — then dispatches
`release-setup.yml --ref setup-v<V>` with `publish_release=true` (dispatch is the documented
exception). Running after the agent release, it can never block or poison it; a failure
goes red with the manual command in the log. `release-setup.yml` pins `target_commitish` to
the built commit (softprops otherwise defaults it to `master`) — since #2013 (2026-10-12) only
when the release creates the tag, because GitHub refuses a target that changes
`.github/workflows` relative to master — drops `skip_macos`, asserts
the dispatched ref matches the version, and opens/closes a release-failure issue like the
agent lane. The newest `setup-v*` then always sits near the top of the 100-release page the
resolver caches, so the resolver needs no change.

### S2 — the wizard icon and the overlay default

`scripts/gen-tray-icons.py` gains `--target desktop|setup`; the setup set is the same R mark
on `#2E7D32` (`icon.png` 512 px, `icon.ico` 16–256 px). The hand-staged macOS `.app` gets
`CFBundleIconFile`. CI's icon guard extends to `agents/meshharbor-setup/icons/` (PNG ≥ 128 px,
ICO with ≥ 5 entries including 256 px), so a placeholder cannot ship again.

The overlay box follows the role until the user touches it: checked for `daemon-system` /
`daemon-machine`, unchecked for per-user roles (a hint explains that the TUN adapter needs a
service install). The orchestrator applies the same default when the option is absent.

### D1 — Routes hold still

1. **One connection per refresh.** `cmd_tunnels_view` reads `RouteList` then `Flows` on one
   LocalAPI connection and returns `{available, reason, routes, flows}`.
2. **Never paint an error as data.** A sequence guard drops stale responses; on failure the
   page keeps the last good data and shows *"live data unavailable since HH:MM:SS · N
   failures · reason"*; rows are keyed by id and patched in place, so a button never moves
   under the cursor. A desktop log records every refresh error.
3. **The pipe always has a spare.** `serve_windows_at` runs a pool of accept tasks (default
   4, `localapi_pipe_pool`, `1` = today's behaviour), each owning one listening instance.
   The client backs off `ERROR_PIPE_BUSY` on `[5, 10, 20, 40, 80, 160]` ms (≤ 315 ms).
4. **Edit a route.** `Request::RouteUpdate { route }` replaces a declared route in one step
   under the config write lock; an invalid replacement leaves the old route running.

### D2 — Settings, grouped

`KEYS` becomes `&[KeyMeta { key, kind, group, tier, live, description }]`, so the compiler
makes every key say where it belongs. Twelve groups (Access & consent · Private network ·
Network carriers & relays · Routing & adapter · Tunnels & SOCKS · MeshHarbor SSH · Remote
desktop · Capture & input · Video encoding · Video rate & latency · Files · Device &
service) and three tiers; an **Essentials** section — `overlay_enabled`,
`auto_grant_session`, `exec_enabled`, `remote_config_enabled`, `ssh_enabled`,
`encoder_preference`, `files_dir`, `power_policy`, `auto_update` — opens by default and every
group below it starts collapsed. `ConfigEntry` gains additive `group`, `group_label`, `tier`
and `default`; `restart_required = !live`, and `live` is true only where the daemon really
applies a change at once. An older daemon without the fields gets today's flat list.

### D3 — Apply now

`Request::RestartDaemon { reason }` restarts the worker through its supervisor. A new
`supervision::detect()` recognises the Windows SCM host and the per-user Scheduled Task (a
hidden `run --supervisor scm|task` they pass), systemd (`INVOCATION_ID`), launchd
(`XPC_SERVICE_NAME = fans.itachi.meshharbor.*`) and the FR-43 macOS supervisor — and **refuses** when
none is present, so an orphan `meshharbord run` is never taken offline. The restart goes
through the existing internal-shutdown path (`mark_clean_shutdown`), so it is not counted as
a crash and cannot trip a rollback; the exit code is `0` under SCM (already *respawn*) and a
new `RESTART_REQUESTED_EXIT_CODE = 9` elsewhere (launchd relaunches only a non-zero exit; 9
is outside systemd's `RestartPreventExitStatus=7 8`). Rate-limited to one per 30 s;
`local_restart_enabled = false` disables it. Remote configuration still never restarts a
daemon — this verb is LocalAPI-only.

As built (`agents/meshharbord/src/supervision.rs`, `localapi_state.rs::restart_daemon`), with
what building it added to the design above:

- **systemd is proven twice.** `INVOCATION_ID` is inherited by every shell under GNOME
  Terminal, so detection also requires this process's cgroup leaf to be one of OUR units, by
  exact name; and before accepting, the daemon reads the unit's *effective* policy back from
  systemd (`systemctl show`: `MainPID`, `Restart`, `Restart{Prevent,Force}ExitStatus`,
  `SuccessExitStatus`) — this pid must be the unit's main process and the policy must
  restart exit 9. Any failure to get that answer refuses.
- **The 30 s record is on disk** (`restart-request.json` beside the config the daemon loaded,
  never inside `config.toml`), written with fsync + rename BEFORE the answer; a restart that
  cannot be recorded is refused, because the record is the loop bound — it binds the
  relaunched process too.
- **The answer reaches the caller before the shutdown starts**: the verb only arms the
  restart; the LocalAPI connection loop calls `restart_commit` after writing
  `DaemonRestarting` (a 5 s fallback commits if that loop never gets there).
- **The exit happens after the runtime is gone**, exactly as an auto-update's exit tears it
  down; only the code differs. An OS stop (`systemctl stop`, `launchctl bootout`) racing an
  accepted restart wins — the process leaves with its ordinary code.
- **More refusals:** a screen recording in progress (a restart would end it — the same work
  the updater defers for), a restart already under way, and — FR-43 only — a worker younger
  than 30 s (its supervisor counts an earlier exit as a failed start and gives up after five).
- **The Scheduled Task's relaunch is the caller's, and a pid says when it is done.**
  `NodeStatus.pid` and `DaemonRestarting.pid` let a caller tell the relaunched daemon from the
  one that is leaving (the old process keeps answering for a moment after it says yes); with
  `restart_by: caller` the caller runs `meshharbord service start` whenever nothing answers,
  again every 3 s — the task's `IgnoreNew` drops a start that lands while the old instance is
  still exiting. One implementation (`meshharbor_localapi::wait_for_restart`) serves the CLI and
  the companion; the companion spawns `service start` with `CreateProcessW` and no inherited
  handles (#1035).
- **`local_restart_enabled` is live** (read from the file per request): an owner's OFF is in
  force for the very next request, and turning it back ON does not need the restart it
  enables.

### D4 — Overview: what this device can encode, and where received files go

`Request::EncoderCaps` returns the probed cells (`ready`), `not_probed` before the first
hello, or `unsupported` on a build without encoders — it reads the OnceLock and never starts
a probe. The Overview card draws codec × backend with chroma, struck-through denied cells,
and the probe time.

`files_dir` (live, Files group, essential) sets where dropped files land. `~` expands against
the **active** user at use time, so one machine config stays right for every user. It must be
absolute, creatable and writable, outside system directories — and when the writer is
SYSTEM/root, inside the active user's profile: the LocalAPI admits interactive non-admin
users, and without that rule one could make SYSTEM write remote-supplied files anywhere. The
rule holds at set time **and** at use time (`download_dir()` validates and falls back with a
warning). The card shows the effective path with Open folder, Change… (the native picker,
which can create a folder) and Use default.

### D5 — Devices: the mesh-visible grid and the mesh graph

- **Server** — `GET /api/agent/self/devices` and `/api/agent/self/mesh`, host-owned (the
  network module is optional), agent-token authenticated through the fleet extractor's
  shared `authenticate()`. The visible set is **self ∪ the join-time netmap shaping**,
  extracted as `shape_full_netmap` from `crates/modules/network/src/overlay.rs:527-550` and
  reused by `handle_overlay_join`, so the list can never show a peer the netmap withholds:
  `off`/`warn` list every live node, `enforce` only the shaped set. The device's own live node
  is found **before** any ACL read (`try_load_acl` creates the network on miss and must never
  run on a GET). Grid logic (`parse_query`/`apply_query`) is extracted from
  `crates/api/src/routes/device.rs` and shared by both listings. Rows carry display name,
  name, OS, version, presence, overlay IP, MagicDNS, tags, reachability and `is_self` —
  never `machine_id`, owner ids, keys, consent or codecs, and fields not returned are blanked
  before search. The mesh payload is the web one restricted to the visible set, edges only
  when both ends are visible, with a server-computed `label` and `self_node_id`.
- **Daemon** — `Request::Devices {org, page, per_page, q, sort, dir}` / `Request::Mesh {org}`
  proxied with the org's agent token; `Response::Upstream {code, message}` names the failure
  (server unreachable, unauthorized, old server, module unmounted, rate limited, unknown
  org); a short single-flight cache; `mh devices` in the CLI.
- **Desktop** — a grid with debounced search, server sort and paging, a column chooser (show
  / hide, drag and ▲▼ reorder) persisted per org, keyed in-place rows, a live
  connection/RTT column merged from the local `Peers` poll, and a vanilla-SVG port of the web
  mesh graph (`ui/src/components/stats/MeshGraph.vue`) whose pure helpers are generated from
  `ui/src/utils/mesh.ts` with a drift test. The list refreshes every 30 s only while the view
  is visible. A new desktop on an old daemon or server falls back to today's peers table.

### D6 — the companion starts after install, and says hello

- **Launch once, from the daemon** — which covers every install path at once, since each of
  them ends with the daemon starting: only when `companion_autostart` is on, the companion
  exists and is not running, an interactive session exists, and no marker says it was
  already launched (the marker is written first). A companion the person quit is never
  relaunched; the consent path's `ensure_running` is unchanged.
- **No inherited handles** — the user-session spawn moves to `CreateProcessW` with
  `bInheritHandles = FALSE` (#1035 found tunnel ports held by a companion whose parent was a
  dead daemon), and a route stuck on `AddrInUse` logs who holds the port.
- **Autostart** — `HKLM\…\Run` for perMachine (written by the elevated `service install`,
  self-healed, removed on uninstall), `HKCU\…\Run` for perUser, xdg autostart on Linux,
  `RunAtLoad` on macOS; a "Start at login" toggle.
- **First run** — the companion reads argv on its first launch too, and shows the Welcome
  view until the person finishes it (per-user state), however it was launched: enrolled as
  `<name>` (or the enroll form) · the private network explained, with **Enable** → Apply now
  → the overlay IP (per-user installs get userspace mode on a free port, explained) · consent
  · where received files land · start at login · done.

### D7 — docs and the install matrix

`docs/desktop-companion.md` (new, indexed), updates to installation, tunnels,
remote-control, api, overlay-communication and deployment docs and the ship-it skill, and a
vmtest `companion-autostart` check on every install cell.

### Compatibility

Every LocalAPI and wire change is additive (`serde(default, skip_serializing_if)`); an
unknown verb is an error the desktop turns into "this service predates …", never a blank
page. Old desktop + new daemon, new desktop + old daemon, and new daemon + old server each
keep today's behaviour for the part the older side lacks.

## Phases

| phase | what | kill switch | status |
|---|---|---|---|
| P0 | spec + ledger row + issue | — | merged #1635 |
| S1 | wizard lockstep + one-time `setup-v0.4.102` re-cut | repo variable `SETUP_LOCKSTEP=false` | merged #1641; re-cut done 2026-09-25; first lockstep release = `agent-v0.4.103` |
| S2 | wizard icon + overlay default for perMachine | revert (assets / UI) | merged #1641 |
| D1 | Routes: one connection, stale-while-error, keyed rows, route edit; LocalAPI listener pool + backoff | `localapi_pipe_pool = 1` restores one instance | merged #1644 |
| D2 | grouped Settings, per-key `live` truth | an old daemon → flat list | merged #1643 |
| D3 | `RestartDaemon` + Apply now | `local_restart_enabled = false` | merged #1663 |
| D4 | encoder-caps card; `files_dir` | `files_dir` unset = today's ladder | merged #1662 |
| D5 | `/api/agent/self/*`, daemon verbs + `mh devices`, grid + mesh | any error → the legacy peers table | merged #1646 (server), #1660 (daemon + desktop) |
| D6 | launch once after install, autostart, Welcome, no-inherit spawn | `companion_autostart = false` | merged #1670 |
| D7 | docs, vmtest check, field log | — | docs merged #1675; vmtest checks in the deploy repo; field log below |
| — | release | — | `agent-v0.4.103` (`aa64d61da`) carries D1–D6; `agent-v0.4.104` (`8611a33f2`) and `agent-v0.4.105` (`771b01b9f`) carry the field fixes |
| — | field fixes | revert | #1682 (#1681: the Welcome's Enable read the service probes' log noise — perMachine got the userspace path); #1688 (#1686: the old companion survived an update) — both ride 0.4.104; #1703 (#1701: an enrolled SystemContext device read as not enrolled — the companion could not read the machine config W4(c) restricts to SYSTEM + Administrators, so it now asks the daemon) — rides 0.4.105 |

New keys (`files_dir`, `local_restart_enabled`, `companion_autostart`, `localapi_pipe_pool`)
are registered in the config surface like every other key.

## Acceptance criteria

- [x] **AC1** — An `agent-v0.4.N` release produces `setup-v0.4.N` at the same commit with no
      human step, and `/api/setup/{windows,linux,macos}` serve 0.4.N.
- [x] **AC2** — The shipped wizard shows a white R on green at 16–256 px (EXE resource and
      `.app`); CI refuses a placeholder icon.
- [x] **AC3** — The wizard's overlay box is checked for perMachine roles and unchecked for
      perUser roles, unless the user changed it.
- [x] **AC4** — With the Routes view open for 10 minutes on the reporting host, no declared
      route or live forward disappears; the 3-open raw pipe probe returns no 231; a failed
      refresh keeps the last data and names the reason.
- [x] **AC5** — Editing a live route's port leaves it `active` on the new port; an invalid
      edit leaves the old route running.
- [x] **AC6** — Settings shows grouped, collapsible keys with Essentials open; search finds a
      key inside a collapsed group; a live key saves without a restart prompt.
- [x] **AC7** — Apply now on a supervised Windows service returns the worker in < 10 s with
      `crash_count` unchanged; an unsupervised `meshharbord run` refuses; systemd and launchd
      hosts verified via `mh exec`.
- [x] **AC8** — The Overview caps card matches `meshharbord caps` on a Windows NVENC/QSV host and
      a Linux VAAPI host; a signalling-only build says "unsupported"; querying it never
      starts a probe.
- [x] **AC9** — The Overview shows where dropped files land; changing it makes the next drop
      land there without a restart; a SYSTEM-context worker refuses a folder outside the
      active user's profile at set time and at use time.
- [x] **AC10** — The desktop grid lists exactly this device's netmap set plus itself
      (integration test with a negative control under ACL `enforce`), shows display names,
      pages / sorts / searches on the server, keeps column order and visibility across
      restarts, draws the mesh for the same set, and no row carries `machine_id`, owner ids
      or keys.
- [x] **AC11** — After install on Win11 (served script and wizard, perMachine and perUser),
      Ubuntu (`install.sh`) and macOS (`.pkg`), the Welcome view is up within 10 s of the
      daemon starting; a companion the user quit is not relaunched by a daemon restart;
      later logins start it in the tray.
- [x] **AC12** — "Enable" in the Welcome view ends with an overlay IP shown (perMachine) or
      userspace mode on a free port with an explanation (perUser).
- [x] **AC13** — A companion the daemon launched holds no handle of the daemon's process
      (handle listing after a daemon restart).
- [x] **AC14** — Docs: `docs/desktop-companion.md` created in house style (page map, data
      sources, autostart per platform, the restart verb, `files_dir` rules, the devices
      visibility rule, mermaid diagrams) and linked from `docs/README.md`; the installation,
      tunnels, remote-control, api, overlay-communication and deployment docs and the
      ship-it skill updated.

## Open decisions

1. **Served-script parity for the overlay default.** `scripts/install.ps1` has no overlay
   option and the Linux `install.sh --system` path passes no `--overlay`. Keeping them as
   they are: flipping the default would silently change corporate automation. Revisit with
   an explicit `--no-overlay` if the operator wants parity.
2. **Tags in the device grid** — shown, as the same class of admin-authored label as
   `display_name`.
3. **Listener pool size** — 4; revisit with field data.

## Out of scope

- #1631 and #1632 — one-PR bugs, tracked on their own.
- `ConferenceView`'s param reuse — a remount there is a leave + join mid-call.
- `display_name` on the netmap wire (`NetmapPeer`) — the legacy fallback keeps netmap names.
- A per-agent rate ceiling on `/api/agent/self/*` beyond the per-IP limiter (the desktop
  polls only while the view is visible).

## Field-verification log

| date | build | observation |
|---|---|---|
| 2026-09-25 | agent 0.4.101 (reporting host) | **Baseline, Routes**: 6 samples of `route ls` + `flows` over 10 s — 7 routes `active`, identical flow ids; 24/24 concurrent `route ls` OK. Raw 3-open pipe burst ×60: open2 = `ERROR_PIPE_BUSY` 60/60, open3 59/60. A .NET `Connect(0)` probe of the same saw 90/90 OK — it waits (`WaitNamedPipe`) where the Rust client does not |
| 2026-09-25 | production | **Baseline, wizard**: `/api/setup/windows` and `/linux` → `0.4.48`; `/api/setup/macos` → 404; `/api/setup/latest-release` → one release, `setup-v0.4.48` (2026-09-02); agent lane at `agent-v0.4.102` |
| 2026-09-25 | `setup-v0.4.102` (re-cut by hand) | **S1, one-time**: `/api/setup/{windows,linux,macos}` → `0.4.102` on all three (macOS was 404); every archive with its `.asc` + `.sha256`. Built by the workflow as it stood at that commit, so `targetCommitish: master` and the placeholder icon — AC1/AC2 are for the first lockstep release |
| 2026-09-25 | agent 0.4.102 (reporting host), before 0.4.103 | **AC4 before**: raw 3-open pipe burst ×60 → open2 `ERROR_PIPE_BUSY` 60/60, open3 60/60. **AC8 before**: the LocalAPI answers `encoder_caps` with `unknown variant` (also on a Linux systemd host) |
| 2026-09-25 | `setup-v0.4.102` wizard (vmtest win11/wizard/user) | **AC3 before**: Back → role → Continue readings of the overlay box: `daemon-user=false daemon-machine=false daemon-system=false` — unchecked for the perMachine roles (want true). **AC2 before**: the wizard EXE's icon at 16/32/48/256 px is one flat translucent red (`#D20000`, alpha 118) — the 1×1 placeholder, stretched |
| 2026-09-25 | `agent-v0.4.103` (`aa64d61da`) | **AC1**: only `agent-v0.4.103` was pushed; `dispatch-setup-release` tagged `setup-v0.4.103` and ran release-setup (green, incl. the alert-close job); `targetCommitish` = `aa64d61da` = the agent commit; `/api/setup/{windows,linux,macos}` → `meshharbor-setup-0.4.103-…` on all three. **AC2**: the 0.4.103 wizard EXE's icon — field `#2E7D32` opaque at 32/48/256 (`#2F7E33` at 16), centre `#FFFFFF` at 256; the `.app` carries `CFBundleIconFile icon.png` (512×512, same design); CI's placeholder guard went red→green in #1641 |
| 2026-09-26 | `setup-v0.4.103` (vmtest win11/wizard/user) | **AC3**: `daemon-user=false daemon-machine=true daemon-system=true`; unticked on `daemon-machine`, then a role flip there and back: `daemon-machine+touched-off=false daemon-user+touched-off=false` — the person's choice sticks. **AC11 (wizard)**: `meshharbor-desktop.exe --first-run` in the console session as the signed-in user, within the cell's window |
| 2026-09-26 | agent 0.4.103 (reporting host) | **AC4**: raw 3-open pipe burst ×60 before and after the window → open1/open2/open3 ok **60/60** each (was open2 `231` 60/60). Routes view open 10 min, 20 samples at 30 s: 7 routes, 7 active, 7 flows in every sample; the desktop's own log recorded 0 failed refreshes in the window. A real failure, the daemon restarting under the open view: the desktop log `refresh failed surface="tunnels" failures=1 reason=device service not running (no LocalAPI endpoint)` → 2 s later `refresh recovered`; the frame in between shows "live data unavailable since 03:27:28 · 1 failure · device service not running (no LocalAPI endpoint)" above all 7 declared routes and the live forwards (the last good data), and the next poll's frame has the banner gone and 7 routes `active`. **AC5**: a throwaway SOCKS5 route `active` + LISTENING on 41190 → `route edit --local 41191` → `active` on 41191, 41190 released → `route edit --local 1081` refused ("already used by another enabled route") and the route kept running on 41191; the operator's 7 routes untouched (against an OFFLINE node the probe read `active` with no listener — #1685). **AC7 (SCM)**: `mh restart` → "pid 52756 exits with code 0; scm relaunches it — back: pid 73676 after 3.6 s", `crash_count` 0→0. **AC13**: after the restart 7/7 declared routes `active` and no listening socket owned by a dead pid. **AC8**: `encoder_caps` = `meshharbord caps` — 12 cells (`av1/h264/hevc_nvenc`, `h264/hevc_amf`, `h264/hevc_d3d12`, `h264/hevc_vulkan`, `h264_mf`, `h264_openh264`, `vp9_libvpx`), `state=ready probe_ms=5693` |
| 2026-09-26 | agent 0.4.103 (a Linux VAAPI host, via `mh exec`) | **AC8**: `encoder_caps` = `meshharbord caps` — 6 cells (`h264/hevc_vaapi`, `h264/hevc_vulkan`, `h264_openh264`, `vp9_libvpx`) |
| 2026-09-26 | agent 0.4.103 (vmtest win11: script + MSI × system / attended / user) | **AC6**: 13 groups; Essentials open with exactly the 9 named keys, every other group closed; searching `localapi_pipe_pool` opened the closed Device group ("1 key matches"), clearing re-closed it; a live key (`files_dir`) saved "in effect now" with no restart bar, a restart-bound key raised it. **AC7**: SCM + SystemContext 4.8 s, SCM attended 5.1 s, MSI SystemContext 9.7 s, MSI attended 6 s; Scheduled Task (script / MSI perUser) "exits with code 9; this command starts it again (task)" → 6.9 s / 7 s; `crash_count` 0→0 on every cell. **AC8**: 3 software cells, card "Software only". **AC9**: SystemContext worker refused `C:\MeshHarborDrops` at set time ("…must be inside the active user's profile (C:\Users\vmtest)…"); `~\Drops` saved live → the Overview shows `C:\Users\vmtest\Drops` with no restart. **AC10**: grid = the anchor + self, self chip, server-side search → exactly this device, the mesh with the self ring, a hidden + reordered column survives a reload. **AC11**: `meshharbor-desktop.exe --first-run` in the console session as the signed-in user (never SYSTEM) on all six; after a quit + `mh restart` no companion from the daemon within 60 s — on the MSI cells a `--autostart` companion appeared whose parent is `explorer.exe` (Windows' own logon Run processing, late on a freshly booted guest), not the daemon. **AC12 (perUser)**: overlay off → the Welcome's network step "Turn on in userspace mode" → "Connected. This computer is 100.65.20.7 … SOCKS5 127.0.0.1:41080". **AC12 (perMachine) ❌**: attended offered userspace mode, SystemContext disabled the button — both #1681 (fix #1682) |
| 2026-09-26 | agent 0.4.103 (vmtest Ubuntu 24.04: script + `.deb` × system / user) | **AC7 (systemd)**: "exits with code 9; systemd relaunches it — back: … after 5.5–5.6 s", `crash_count` 0→0 on all four. **AC11**: `/usr/bin/meshharbor-desktop --first-run` as the user; a quit companion stays quit through a restart |
| 2026-09-26 | agent 0.4.103 (a WSL host with a virtual desktop) | **AC7**: `mh restart` → "exits with code 9; systemd relaunches it", new pid, `crash_count` 0→0, `NRestarts` 1→2 — but **96 s** later: the host's `at-spi-bus-launcher` ignored SIGTERM, so systemd waited `TimeoutStopSec` (90 s) + `RestartSec`, and the CLI gave up at 60 s (#1684) |
| 2026-09-26 | agent 0.4.102 → 0.4.103 (reporting host, auto-update) | **Found #1686**: the old companion survived the update and the new one could not start (Tauri's single-instance lock) — the refresher finds and kills it by IMAGE NAME, and by then Windows listed the companion the previous refresh respawned under an NTFS file id. Both the service host and its worker ran the refresh. Fix #1688 (one refresher per install; found by its started-from path, stopped by PID before the swap) |
| 2026-09-26 | agent 0.4.102 → 0.4.103 (vmtest win11 MSI attended, the daemon's own updater) | **#1686 before-run**: host `refreshing` 01:08:41.6 → `respawned=true` 01:08:43.9; worker `refreshing` 01:08:42.3 → `respawned=true` 01:08:44.9 — two refreshers, the companion closed and reopened twice in 3 s. This interleaving was benign (the worker checked after the host's respawn); the reporting host's was the other one. A hand-run `meshharbord self-update` over SSH is not a substitute: MSI 1601 twice. Side findings: #1689 (`rc:agent.update` on `auto_update = false` is swallowed silently), #1690 (the `self-update` CLI purges the running service's routes and DNS steer) |
| 2026-09-26 | agent 0.4.103 (container on a Linux host, `meshharbord run` as PID 1, no supervisor) | **AC7 (orphan)**: `mh restart` → rc 1, "the daemon refused to restart: this service is not running under a service manager it can identify … exiting would stop it for good rather than restart it"; still running, pid 1 → 1 |
| 2026-09-26 | agent 0.4.103 (vmtest win11 MSI attended) | **AC13**: the companion the worker respawned in the post-update refresh (its parent has exited), after three daemon restarts: 302 handles — no socket (`\Device\Afd`), no daemon log or config, no `ProgramData\meshharbor` path, no meshharbor pipe, no process handle to a `meshharbord`; its files are the WebView2 runtime's, its own `desktop.log` and system resources; no listener owned by a dead pid. The listing's sanity check (the companion's known WebView2 process handles present) guards against an empty read |
| 2026-09-26 | agent 0.4.103 (vmtest win11 MSI attended, reboots with autologon) | **AC11 (later logins)**: the tour marked done — the state a finished or skipped tour leaves — then a reboot: the HKLM `Run` login start (`--autostart`, parent `explorer.exe`) logged `action=Tray first_run_done=true`, and no `MeshHarbor` window was on screen (a window list taken inside the console session). Control, no tour state: the same start logged `action=Show("welcome")` and the window was up. With `companion_autostart = false` both starts leave at once (`login start on a device whose companion_autostart is off — leaving`) — the kill switch, which the vmtest settings probe had flipped (it now puts it back) |
| 2026-09-26 | agent 0.4.103 (a macOS host, the root launchd daemon, via `mh exec`) | **AC7 (launchd)**: `mh restart` → "pid 20382 exits with code 9; launchd relaunches it — back: pid 97139 after 1.0 s"; `launchctl print`: runs 1 → 2, last exit code 9; `crash_count` 0 → 0; both orgs reconnected; the running companion untouched. **AC11 (macOS `.pkg`)**: the 0.4.102 → 0.4.103 upgrade through the root update helper — `installer -pkg` 08:13:17 → the companion the postinstall started, 08:13:18.7, `action=Show("welcome") first_run_done=false` → the daemon up at 08:13:21.9: the Welcome was up before the daemon. An upgrade, not a fresh install; the postinstall that launches the companion is the same |
| 2026-09-26 | agent 0.4.103 (the released `.deb`, a container on a Linux host) | **AC8 (never probes)**: `server_url` pointed at a refusing port, so no hello can happen: 8 `encoder_caps` queries over 40 s → `state=not_probed` every time, no `caps-probe` child, no `caps probe:` log line. Control, the real server: the hello's probe ran (`child reported elapsed_ms=50 … cells=2`) and the same query then read `state=ready probe_ms=50 cells=2` |
| 2026-09-26 | a signalling-only build of master `08c2749` (`cargo build -p meshharbord --release`, no features; a container on a Linux host) | **AC8 (unsupported)**: enrolled and running, `encoder_caps` → `state=unsupported cells=0` at start and again after its `rc:agent.hello`; no `caps-probe` child |
| 2026-09-26 | agent 0.4.103 (vmtest win11 MSI SystemContext; drops from the production web viewer) | **AC9**: the person at the console set `~\DropsA` → "in effect now — no restart needed" (`applies="live"`) → a 256 KiB drop landed in `C:\Users\vmtest\DropsA`, SHA-256 identical; they set `~\DropsB`, no restart → the next drop landed in `C:\Users\vmtest\DropsB`, identical. Use time: `C:\MeshHarborDrops` written into the config behind the daemon's back + a restart → the drop logged `files: configured files_dir refused - this transfer lands in the default folder … must be inside the active user's profile (C:\Users\vmtest)` and landed in `C:\Users\vmtest\Downloads`, identical; `C:\MeshHarborDrops` was never created. Set time: refused through the companion (the cell's probe), and a set from anyone but the person at the console is refused outright ("only the person at this device's console can change where incoming files land") |
| 2026-09-26 | `agent-v0.4.104` (`8611a33f2`; vmtest win11 MSI attended + SystemContext) | **AC12 (perMachine, attended) ✅**: the Welcome's network step now offers "Turn on the private network" (the TUN path; 0.4.103 offered userspace) and ends "Connected. This computer is 100.65.20.4 on your private network." — #1682 in the field. **AC12 (SystemContext) ❌**: the label was right but Enable was disabled; step 1 read "Not enrolled yet" next to "● Connected". A second, independent cause, **#1701**: the companion read the machine-global config, which W4(c) restricts to SYSTEM + Administrators (as the console user `Get-Content` → *Access is denied*, while `mh status` over the LocalAPI → enrolled). Fix #1703: the companion asks the daemon when it cannot read the file. A side-load of #1703 on the same guest turned `welcome-enable` FAIL → PASS. **#1686 after-run ✅**: 0.4.103 → 0.4.104 through the daemon's own updater — one refresher (the service host), the old companion stopped by PID, one companion running from the live image |
| 2026-09-26 | `agent-v0.4.104` (fresh vmtest win11 MSI SystemContext) | **AC12 negative control, the same day as the fix shipped**: `welcome-enable` FAIL on a fresh 0.4.104 SystemContext cell (#1701) |
| 2026-09-26 | `agent-v0.4.105` (`771b01b9f`; fresh vmtest win11 MSI SystemContext + attended, the shipped MSI) | **AC12 (SystemContext) ✅**: overlay off → Apply now → the Welcome's network step state "Off", "Turn on the private network" → "Connected. This computer is 100.65.20.4 on your private network." **AC12 (attended) ✅** again on the shipped build ("… 100.65.20.3 …"). Every other cell check passed on both — install, enroll, overlay, companion autostart, restart-supervised 6.6–6.9 s with `crash_count` unchanged, RC frames, the six desktop views, settings groups + live save (SystemContext refused `C:\MeshHarborDrops`, saved `~\Drops` live), caps card = `meshharbord caps`, devices grid / mesh / columns |
