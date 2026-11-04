# FR-56 — Remote Apps on Wayland: per-app streaming, and the RAIL circle

**Issue:** [#1157](https://github.com/gjovanov/roomler-ai/issues/1157) · **Status:** **P1/P2/P4/P5 shipped and field-verified** (agent-v0.4.48); **P3 REFUTED — GNOME refuses it**; **P6 — the AC10 honesty audit — fixed in PR [#1667](https://github.com/gjovanov/roomler-ai/pull/1667), shipped in agent-v0.4.103; the agent half field-verified 2026-09-26, the viewer's P2 + P5 rendering field-verified 2026-10-07 in a live session on prod 0.4.116; a *refusal* rendered in a dialog still owed — no host in a refusing state exists in the fleet (AC10 `[~]`)**; docs page [`docs/remote-apps.md`](../remote-apps.md) merged with it · **Owner:** agent / remote-control

> ⚠️ **Renumbered from FR-55**, which [#1155](https://github.com/gjovanov/roomler-ai/pull/1155)
> landed on master while this claim was in flight. The **ledger arbitrated**: a claim that
> never reached master is the one that moves, and the lower-issue-id repair applies only
> when two claims BOTH landed — invoking it here would have forced an already-merged FR to
> renumber, which is exactly the churn that rule exists to prevent. Renumbered to the next
> free N, never into a vacated one.

## Goal

Make **Viewer settings → Session → Remote Apps** work on a **Wayland** host —
list windows, focus one, launch an allowlisted app — and let a viewer stream a
**single application window** instead of the whole desktop.

That last part is the circle: [FR-45](FR-45-portal-capture.md) made a Wayland
desktop capturable (portal, then `org.gnome.Mutter.ScreenCast` direct), and
WSLg has been doing per-window remoting on the same machine the whole time —
Weston with `rdp-backend.so` + **`rdprail-shell.so`**, so each Linux window
arrives as its own native Windows window. We capture whole desktops; RAIL
capture is what turns "a screen" into "an app".

## Why now, and what is actually broken

Remote Apps exists and is good (`agents/meshharbord/src/apps/`, three verbs over
the control DC, allowlisted launch, tmux-backed sessions that survive a
restart). It is also, on Linux, **X11-only and gated on the daemon's own
`DISPLAY`** — so on every Wayland host it does not fail, it never engages.

Measured 2026-09-01 on the WSL2 dev box (headless `mutter` + Xwayland) and
cross-checked against the code:

| # | Measurement | Consequence |
|---|---|---|
| 1 | `apps_supported()` is literally `std::env::var_os("DISPLAY").is_some()` (`apps/mod.rs:152`) | The daemon runs as **root under systemd with no `DISPLAY`**, so a Wayland host always answers `supported:false` |
| 2 | `handle_control_message` reads the **daemon's** `DISPLAY` (`apps/mod.rs:~202`), set process-global only by `virtual_desktop` | The feature is structurally bound to Xvfb mode |
| 3 | `linux.rs:58` sets `DISPLAY` on the child but **never `XAUTHORITY`** | With `DISPLAY` alone `wmctrl` fails `Authorization required, but no authorization protocol specified` |
| 4 | mutter starts **Xwayland** on a headless Wayland desktop (`Using public X11 display :0`) | X11 tooling *does* work there — the feature is far closer than it looks |
| 5 | With `DISPLAY=:0` **and** `XAUTHORITY=/run/user/<uid>/.mutter-Xwaylandauth.*`: `wmctrl -l` listed a launched `roomler:app:test` window and `wmctrl -i -a` **focused it (rc=0)** | P1 is plumbing, not new capability |
| 6 | Native Wayland clients (`foot`, `gnome-text-editor`) were **alive and absent** from `wmctrl -l` | X11 tooling cannot see native Wayland windows — ever |
| 7 | Full protocol list of that mutter: `gtk_shell1 wl_compositor(6) wl_shm wl_seat wl_output wp_* xdg_activation_v1 xdg_wm_base(6) zwp_* zxdg_*` — **no `zwlr_foreign_toplevel_management_v1`, no `ext_foreign_toplevel_list_v1`** | There is no way to enumerate other apps' windows on mutter |
| 8 | No `gnome-shell` on the bus (bare mutter) ⇒ no `org.gnome.Shell.Introspect` | The one GNOME enumeration API needs a full shell, not just a compositor |
| 9 | `xdg_activation_v1` **is** present | It is token-based *self*-activation; it does not let us focus a third party's window |

🔑 **The honest headline:** the circle closes cheaply for **Xwayland** apps, and
for **native Wayland** apps only on compositors that expose a foreign-toplevel
protocol. **GNOME deliberately does not** — window management is the
compositor's private business there, and no amount of code on our side changes
that. This FR must ship that asymmetry as a *reported capability*, not discover
it per host.

## Design

| Phase | What | Kill switch |
|---|---|---|
| **P1** ✅ | **Make the existing feature engage on Wayland.** Replace the daemon-`DISPLAY` gate with **session discovery** — FR-45 already built `companion::graphical_session()` (uid, `DISPLAY`, `WAYLAND_DISPLAY`) for exactly this — and pass **`XAUTHORITY`** with `DISPLAY` into every `wmctrl`/`xterm` call. Result: list/focus/launch for Xwayland windows on GNOME/KDE/wlroots. ⚠️ Must be a **byte-for-byte no-op for the Xvfb path**, which is the only population using this today. | existing `[virtual_desktop_apps] enabled` |
| **P2** ✅ | **Say what is actually visible.** `supported: bool` cannot express "X11 windows only" — the exact `Some([])` vs `None` mistake this project has now made on three surfaces (overlay ACL, `ssh_activity`, FR-49's dark org). Add a `sources` field (`x11` / `wayland` / both) plus a human reason, so the panel can say *"showing X11 (Xwayland) windows; this compositor does not let us enumerate native Wayland windows"* instead of showing a short list that looks like the truth. | n/a (wire additive) |
| **P3** ⛔ **REFUTED on GNOME (2026-09-01), not built** | **Native enumeration where the compositor allows it.** `zwlr_foreign_toplevel_management_v1` on wlroots (list + **activate** + close — full parity, and the only tier where focus works) and `org.gnome.Shell.Introspect.GetWindows` on a full GNOME (list **only**; there is no activate). Detected **at session time, never cached** — FR-45's rule, learned from a host that had every package and still offered nothing depending on start order. | `apps_wayland_enum` (default off until field-proven) |
| **P4** ✅ **portal-picker half shipped; `RecordWindow` half unreachable** | **Per-window capture — the RAIL payoff.** Portal `SelectSources(types = WINDOW)`: the *host* picks, so no enumeration is needed and it works wherever a portal backend runs. Reuses the whole FR-45 P3 pipeline — POD negotiation, buffers, wire format, `ScreenCapture` — with only the source mask changed, exactly as P5 did. ⛔ The `org.gnome.Mutter.ScreenCast.RecordWindow` route is **not buildable**: it takes a window id and P3 measured that GNOME refuses the only API that could supply one. 🔑 That leaves per-window capture **attended by construction** — the portal answers by showing a picker, so on a host with nobody at it the capture never starts, which is why the switch defaults off and says so in its own config description. | `MESHHARBORD_WINDOW_CAPTURE` (default off) |
| **P5** ✅ **reshaped by measurement, then shipped** | **Launch honestly.** The phase was written as *pick a Wayland terminal where there is no Xwayland* — and measuring first refuted that (see the log: a Wayland-native window is **invisible to `wmctrl`**, so preferring one would trade a visible failure for a silently unmanageable window, and GNOME/KDE run Xwayland anyway). What the same session *did* expose is a real lie: `supported: true` on a host with **no `tmux`**. So P5 ships the honesty instead — `Coverage.missing_tools` names each absent helper and what it blocks, **before** the click rather than as an error after it. | n/a (wire additive) |
| **P6** ✅ **audited and fixed 2026-09-25 (PR [#1667](https://github.com/gjovanov/roomler-ai/pull/1667)), shipped in agent-v0.4.103; the agent half field-verified 2026-09-26; the viewer's P2 + P5 rendering field-verified 2026-10-07 in a live session (prod 0.4.116); a refusal rendered in a dialog still owed — no refusing host exists** | **Degrade honestly on every tier — AC10.** The audit walked every path where Remote Apps is unavailable or partial and asked two questions of each: *is anything advertised that the host cannot do*, and *does the refusal carry its reason in the reply*. Three findings. (a) The viewer's parser **dropped `missing_tools`** — P5's field reached the wire and never the screen (P5 was field-verified with the host-side probe, not the panel; `#1179` added the interface and the template, not the parse). (b) Every `supported: false` was **bare**, so the dialog read *"No windows reported"* — a calm desktop — for a headless host, a Wayland host without Xwayland, a disabled config, a failed privilege drop and macOS alike; the reason lived in a `debug!` line or nowhere (`discover()` swallowed two of them with `.ok()?`, and reported a failed privilege drop as "no Xwayland"). (c) A session host without `wmctrl` **advertised `list`**, so the "install wmctrl" message could reach the operator through the list error. Now: `unavailable: {code, reason}` (a closed set — `disabled` · `no_session` · `no_x_display` · `cannot_run_as` · `tool_missing` · `platform`) rides every refusal on all three verbs; the hello adds **`status`** ("this build has a backend and answers honestly") so the entry shows and the **live reply** carries the truth — the hello is a boot-time snapshot (`detect()` is memoized), so `list` missing from it can just mean nobody had logged in yet; a `wmctrl`-less session host no longer advertises `list`; `roomlerd apps-probe` loads the device's own `[virtual_desktop_apps]` instead of the built-in default. The audit table is in [`docs/remote-apps.md`](../remote-apps.md) §3. | n/a (wire additive; a viewer that ignores `unavailable` sees exactly the pre-P6 reply) |
| **Docs** 📘 (2026-09-25, added retroactively — see the criterion) | [`docs/remote-apps.md`](../remote-apps.md): the three verbs and their wire, how the Linux backend finds a desktop and as whom, the tier-by-tier honesty table (what is advertised, what the reply says, what the panel shows), launch and the tmux session model, per-window capture, the field table, configuration, code map; cross-linked from `remote-control.md` §18.2, `linux-capture.md` §7 and `ui.md`; a `docs/README.md` row. | n/a |

### What this does NOT try to be

Window *management* — move, resize, close, tile — is out of scope; focus is the
one operation the panel needs. Windows RAIL parity (drawing each remote window
as a separate local window in the browser) is out of scope: the viewer renders
one video surface, and changing that is a much larger UI program than this.

## Acceptance criteria

- [x] On a **Wayland** host with no Xvfb, the backend lists windows instead of
      reporting the feature unsupported — verified on Asahi (GNOME Wayland) as
      **root with no `DISPLAY` and no `XAUTHORITY`**, i.e. exactly the daemon's
      own environment: `apps supported: true`, `windows: 1`, and a real window
      title. The **before** is master's gate itself — `apps_supported()` was
      literally `env::var_os("DISPLAY").is_some()` and the daemon has none, so
      it answered `false` by construction. ⚠️ Not yet driven from the browser
      panel end-to-end; that needs a live session and is the remaining half
- [x] `wmctrl` is invoked with **both** `DISPLAY` and `XAUTHORITY`, and the
      fix is proven to be the thing that fixed it: with `DISPLAY` alone — what
      the pre-FR-56 code passed — the same call dies `Authorization required,
      but no authorization protocol specified`; with the discovered cookie it
      lists the window
- [x] The **Xvfb** path is unchanged: a daemon that HAS a `DISPLAY` still
      takes that arm first and runs as the daemon (no discovery, no privilege
      drop). Shown by pointing it at `:99` — it used the daemon's display
      rather than discovering the live session beside it
- [x] The panel **names what it cannot see**: the reply carries a `coverage`
      object (`sources` + `unlisted`), and on a real GNOME Wayland session the
      agent reports `sources: x11` / `NOT listed: native Wayland windows: this
      compositor exposes no protocol to enumerate them`. An empty list and an
      unenumerable source are now distinguishable — including on the ERROR
      arm, which is where an empty list is most likely to be read as calm
- [~] ⛔ **Not attempted — refuted on GNOME and unfalsifiable elsewhere.**
      `org.gnome.Shell.Introspect.GetWindows` exists but answers **`Access
      denied` / "GetWindows is not allowed"** (GNOME Shell 48.8, two different
      D-Bus clients, running AS the session user), and the interface exposes no
      activate method at all — so GNOME is not "list-only", it is **refused**.
      wlroots' `zwlr_foreign_toplevel_management_v1` would give list + activate,
      but **no host in this fleet runs wlroots**, so building it now could only
      be verified in a synthetic sway-in-WSL2 rig — which is the kind of "CI
      green ≠ done" claim this project rejects. Revisit when a wlroots host
      exists
- [x] Asking for a window **reaches the portal as a window request**, and the
      grant is kept apart from the monitor grant. Verified on Asahi (GNOME
      Wayland): that portal advertises `AvailableSourceTypes = 7`
      (`MONITOR|WINDOW|VIRTUAL`), the helper announces *recording ONE WINDOW*
      and then **blocks on the picker** with nobody at the screen — the
      attended-by-construction property observed rather than assumed. Four
      token files now exist (`portal-restore-token{,-rd,-win,-rd-win}`) because
      a window grant and a monitor grant are different grants and reusing one
      file would burn whichever was stored first
- [ ] A single application window is streamed to the browser, and switching
      between two windows is shown to change what the viewer sees. ⚠️ **Needs a
      human at the host** to answer the picker — it is not something this
      agent can complete unattended, and a synthetic pass would prove nothing
- [x] The reply **names the helpers this host does not have**, before the
      click. Field-verified on Asahi, and the run carries both arms: `tmux` is
      reported missing (ground truth: absent) while `xterm` is **not** reported
      (ground truth: `/usr/bin/xterm`) — a probe that simply reported
      everything would pass the first half and fail the second
- [ ] ~~Launch works on a Wayland host with no Xwayland at all~~ — ⛔ **not
      buildable as written, and it would be a regression if it were.** A
      Wayland-native window cannot be listed or focused (measured), so a
      Wayland-native terminal would launch a window the panel can neither
      show nor raise. Every host in this fleet runs Xwayland, where `xterm`
      is the only *manageable* choice
- [~] Every tier degrades honestly: no host reports a capability it does not
      have, and the reason is in the reply rather than only in the daemon log
      — **audited 2026-09-25 and found false three ways on 0.4.102** (P6 in
      the table above; the row-by-row table is `docs/remote-apps.md` §3): the
      viewer dropped `missing_tools` before the screen, every
      `supported: false` was bare and rendered as a quiet desktop, and a
      session host without `wmctrl` advertised `list`. Fixed in PR [#1667](https://github.com/gjovanov/roomler-ai/pull/1667)
      (agent + viewer), shipped in **agent-v0.4.103**. **Half met, half
      blocked (2026-09-26):** ✅ **the agent half is field-verified on
      0.4.103** — `roomlerd apps-probe` with no display, on two headless
      cluster nodes, prints `reason [no_session]: No active graphical login
      session on this host — nobody is at its screen — …` where 0.4.102's
      only possible output on that arm was the fixed paragraph *"no
      manageable desktop found. Either apps are disabled in the config, or
      there is no X display…"*; the same node's Daemon arm is unchanged (AC3);
      the GNOME Wayland host's live arm still names `tmux`; and every online
      0.4.103 Linux/Windows device advertises `status · list · focus · launch`
      (macOS none), each probed host's hello matching its live state.
      ✅ **The viewer's P2 + P5 rendering is field-verified (2026-10-07, prod
      0.4.116 serving the P6 viewer, agent 0.4.116)**: in a live session to the
      GNOME Wayland host the Apps dialog rendered, verbatim, *Not listed —
      native Wayland windows: this compositor exposes no protocol to enumerate
      them (X11/Xwayland windows are listed)* and *tmux is not installed on
      the agent host — persistent shell sessions (the ones that survive an
      agent restart) (apt install tmux)* beside the one Xwayland window — the
      P5 line that never reached a screen before P6 — under P6's button title.
      ⛔ **Still owed: a refusal reason rendered in a dialog.** No host in a
      refusing state exists: every online Linux/Windows hello carries `list`,
      the cluster nodes run the daemon's own Xvfb, the Wayland host has a login
      session, and the WSL node runs its own Xvfb too (its remote view connects
      to it; an earlier note that it "hands the connection to the Windows host"
      was a mis-targeted click on the adjacent device's "Connect to agent" link,
      ruled out by a wire-level repro on 2026-10-07). The refusal's content is verified on
      the agent (0.4.103, `reason [no_session]`), its rendering by the parser
      tests only. Becomes `[x]` when a dialog on a host whose live reply
      refuses — a Linux host with nobody logged in and no Xvfb, or the Wayland
      host after its user logs out — shows the `no_session` reason instead of
      *"No windows reported"*
- [x] **Docs updated/created with diagrams, linked from `docs/README.md`** —
      [`docs/remote-apps.md`](../remote-apps.md): the three verbs and their
      wire as a `mermaid` sequence diagram, session discovery and the
      privilege-drop rule as a `mermaid` flowchart, the tier-by-tier honesty
      table AC10 was audited against (hello · reply · panel, per tier), the
      `coverage` / `unavailable` contracts and why the hello is a boot-time
      snapshot, launch and the tmux session model, per-window capture (P4),
      the field table, the `[virtual_desktop_apps]` configuration and the
      probe, a code map with `file:line` anchors verified against master.
      Indexed in `docs/README.md`, and cross-linked from `remote-control.md`
      §18.2, `linux-capture.md` §7 and `ui.md`. ⚠️ **Added retroactively
      (2026-09-25)**: FR-56 opened on 2026-09-01, before the
      docs-before-close rule (#1401, 2026-09-05), and a close after that date
      binds it. Marked rather than backdated, so the spec does not claim it
      always complied. Ticked when the page has merged. **Merged 2026-09-25 as `990023c6d` (#1667)** and
      checked on master: `docs/remote-apps.md` (410 lines, 2 mermaid
      diagrams), indexed at `docs/README.md:92` with its map node.

## Open decisions

- **Does P4 reuse the FR-45 helper process or spawn its own?** Reuse is
  tempting (one session, one consent) but the helper currently owns exactly one
  stream; per-window capture may want a second concurrent one.
- ~~**Should the backend prefer a Wayland-native terminal?**~~ **Settled by
  measurement (P5): no.** A native window is invisible to `wmctrl`, so
  preferring one would launch something the panel can neither list nor focus —
  trading a *visible* failure for a *silent* one, which is the exact trade this
  FR exists to stop making. The same reasoning applies to exporting
  `WAYLAND_DISPLAY` into launched apps: it would flip toolkit apps from
  Xwayland (manageable) to native (unmanageable), so this backend deliberately
  stays X11-only for BOTH listing and launching — one rule, honestly reported,
  rather than a listing rule and a contradictory launching rule.
- ✅ ~~**Is GNOME enumeration worth it at list-only?**~~ **ANSWERED 2026-09-01,
  and the premise was wrong: it is not list-only, it is DENIED.** Measured
  against a real GNOME session (Shell 48.8) as the session user, via both
  `busctl` and `gdbus`: `GetWindows` → `Access denied: GetWindows is not
  allowed`; `GetRunningApplications` → likewise. The refusal is silent on the
  shell side too (nothing in its journal). GNOME gates Introspect to callers it
  trusts, and a fleet agent is not one. 🔑 So the question "is a list without
  focus worth shipping" never arises — there is no list.
- ~~**Portal WINDOW capture shows a host-side picker.**~~ **Settled by
  measurement (P4).** It is a second consent surface, nobody answers it on an
  unattended host, and the mutter-direct escape hatch turned out not to exist
  (P3: `RecordWindow` needs an id GNOME will not give). So per-window capture
  is attended-only on every host in this fleet — shipped behind a default-off
  switch that states this in its own description, rather than left unbuilt.

## Field-verification log

| Date | What | Result |
|---|---|---|
| 2026-09-01 | Feasibility measured before any code (see the table above) | The circle closes for Xwayland cheaply (P1 is plumbing: `DISPLAY`+`XAUTHORITY` and session discovery, both already built by FR-45); native Wayland enumeration is **compositor-dependent and impossible on GNOME**, which is a capability to report, not a bug to fix |
| 2026-09-01 | ✅ **P1 shipped and field-verified on Asahi (GNOME Wayland)** | As **root with no `DISPLAY` and no `XAUTHORITY`** — the daemon's actual environment — the backend now discovers the session (`display=:0 user=<session owner> xauthority=/run/user/<uid>/`.mutter-Xwaylandauth.*`) and reports `apps supported: true`, `windows: 1` with a real title. Before, `apps_supported()` was `env::var_os("DISPLAY").is_some()` and answered **false** by construction. Proof the cookie is the fix: `DISPLAY` alone (what the old code passed) dies `Authorization required, but no authorization protocol specified`; `DISPLAY`+`XAUTHORITY` lists the window. |
| 2026-09-01 | 🚨 **Found a PRE-EXISTING silent failure while field-testing P1** | `list()` parsed `wmctrl -l`'s stdout **without checking its exit status**, so a display it could not open — empty stdout, non-zero exit — returned `Ok(vec![])`: *no windows*, which is a different and far more reassuring claim than *I could not reach the desktop*. Measured by pointing the daemon at `:99` (no X server): it reported `windows: 0`. `focus` and `tmux new-session` already checked; only this one did not. 🔑 P1 makes it matter: the display is now **discovered** rather than owned, so it can go stale (a compositor restart invalidates the cookie) where a daemon-started Xvfb could not. Now: `list failed: wmctrl could not read the window list from :99: Cannot open display.` |
| 2026-09-01 | ⚠️ **rustc 1.95 ICEs while RENDERING a real error here** | A `tracing::info!(%display, …)` whose local was named `display` collides with tracing's own `field::display` helper, and rustc panicked (`slice/index.rs`, empty query stack) instead of printing the error — `cargo check` reported only *the compiler unexpectedly panicked*. 🔑 `--message-format=short` bypasses the renderer and showed both real errors immediately. A/B'd against clean master first (it compiles), per the standing rule. |
| 2026-09-01 | 🔧 **`roomlerd apps-probe` added** | Remote Apps was answerable only by driving it over a WebRTC data channel from a browser, which conflates the backend with signalling, transport and the UI — the same argument `capture-smoke` was built on. It prints whether a desktop was found, as whom, with which cookie, and what it sees; and it says explicitly that an EMPTY list is not the same as unsupported, and that native Wayland windows would not appear even if present. |
| 2026-09-01 | ✅ **P2 shipped and field-verified** | The list reply carries `coverage` (`sources` + `unlisted`) end to end: agent → wire → composable → panel. On the real GNOME Wayland session the daemon reports `sources: x11` and `NOT listed: native Wayland windows: this compositor exposes no protocol to enumerate them`, beside the one Xwayland window it CAN see. 🔑 The trait method (rather than a field set at construction) means **the compiler forces every backend to answer** — it caught the test fake immediately. ⚠️ Coverage rides the ERROR arm too: a failed listing is exactly where an empty list reads as a calm desktop. ⚠️ The UI parses it defensively and an absent `coverage` stays absent — inventing an empty one would claim the listing was complete, which is the bug this phase exists to fix. |
| 2026-09-01 | ⛔ **P3 REFUTED — GNOME does not merely lack window enumeration, it REFUSES it** | `org.gnome.Shell.Introspect.GetWindows` is present and correctly typed (`a{ta{sv}}`), and calling it as the session user returns **`Access denied` — "GetWindows is not allowed"**. Reproduced with **two independent clients** (`busctl` and `gdbus`) on **GNOME Shell 48.8**; `GetRunningApplications` is refused identically, and gnome-shell logs nothing about either. The interface also has **no activate/focus/raise method at all** (0 matches on introspection), so even a granted listing could never drive the panel's one action. 🔑 The spec's open question — *is a list without focus worth shipping?* — is therefore moot: there is no list. ⚠️ wlroots' `zwlr_foreign_toplevel_management_v1` WOULD give list+activate, but **no fleet host runs wlroots**, so building that tier now could only be "verified" in a synthetic rig. Not built; recorded instead. |
| 2026-09-01 | ✅ **P4 shipped (portal-picker route) and field-measured on Asahi** | `SelectSources(types=WINDOW)` behind `MESHHARBORD_WINDOW_CAPTURE` (default off). That host's portal advertises `AvailableSourceTypes = 7` (`MONITOR\|WINDOW\|VIRTUAL`), so the picker route is available; the helper logged *recording ONE WINDOW (the portal will show a picker)* and then **blocked until the 20 s timeout** with nobody at the screen. 🔑 That timeout **is the result**, not a failure: it is the attended-by-construction property observed instead of assumed, and it is why the switch defaults off and says so in its own config-surface description. ⛔ The mutter-direct half (`RecordWindow`) is **unreachable, not unimplemented** — it takes a window id and P3 measured that GNOME refuses the only API that could supply one, so there is no unattended per-window path on GNOME at all. ⚠️ The restore token had to split **four** ways (`portal-restore-token{,-rd,-win,-rd-win}`): a window grant and a monitor grant are different grants, and sharing the file would burn whichever was stored first — the same reason the input grant already lived apart. The test asserts all four differ **as a set**, because asserting only that two differ would pass with three of them colliding. |
| 2026-09-01 | ⛔ **P5's premise refuted before a line was written — a Wayland-native window cannot be managed** | The phase said *pick a Wayland terminal where there is no Xwayland*. Measured on Asahi instead: launched `konsole` with **only** `WAYLAND_DISPLAY`+`XDG_RUNTIME_DIR` (no `DISPLAY`) — it ran, and `wmctrl -l` **could not see it**; the same test with `xterm` through Xwayland listed as `roomler:p5probe` immediately. 🔑 So preferring a Wayland-native terminal would launch a window the panel can neither list nor focus — trading a *visible* failure for a *silent* one, which is precisely what P2 exists to stop. It is also near-unreachable: GNOME/KDE start Xwayland by default (`Xwayland :0 -rootless` was running on this host), so *no Xwayland at all* is not a configuration this fleet has. ⚠️ Same reasoning kills exporting `WAYLAND_DISPLAY` into launched apps: it would flip toolkit apps from Xwayland (manageable) to native (unmanageable). This backend stays X11-only for **both** listing and launching — one rule, honestly reported. |
| 2026-10-07 | ✅ **AC10 viewer-half read — a live session on prod (server 0.4.116 serving the P6 viewer since the 0.4.105 promote; agent 0.4.116)** | From the worker's own tab in the shared Chrome, after a read-only account check (3 orgs, 28 devices, 20 online). **GNOME Wayland host**: session `connected` (VP9 4:2:0 SW · direct · dec HW · 1920×1080 · ~25 ms), Viewer settings → Session → *Remote apps*; the dialog as rendered, 3 s after the request: `Apps / Open windows / Wayland to X Recording bridge — Xwayland Video Bridge / Not listed — native Wayland windows: this compositor exposes no protocol to enumerate them (X11/Xwayland windows are listed) / tmux is not installed on the agent host — persistent shell sessions (the ones that survive an agent restart) (apt install tmux) / Launch new / New bash session`; the entry's title read *List, focus or launch apps on the controlled host*. P2 and P5 on a screen at last; the tab was hidden the whole time and the read landed before any watchdog teardown. **A refusal in a dialog — not reachable**: the viewer's roster has no online hello that is `status` without `list`; the cluster nodes are Xvfb hosts, the Wayland host has a session, macOS hides the entry. The one unprobed Linux host (the WSL node) was tried twice and **its remote view handed the connection to the Windows host on the same machine both times** — the viewer navigated to that device and connected there (disconnected at once); an observation for the operator, not FR-56's bug, not chased. AC10 stays `[~]`: the refusal's *content* is proven on the agent, its *rendering* by the parser tests only. |
| 2026-09-26 | ✅ **AC10 release-time read, agent half — agent-v0.4.103 on the fleet** | The 09-25 audit is the fail-first. **Headless arm, two cluster nodes** (they run the daemon's own Xvfb, so the Daemon arm wins unless the probe drops `DISPLAY`; `env -u DISPLAY roomlerd apps-probe` walks the session arm on a host with no graphical login session — the `no_session` tier): **before** (0.4.102, the binary's only possible output on that arm) *"no manageable desktop found. Either apps are disabled in the config, or there is no X display: a virtual-desktop host sets one, and on a real session the compositor's Xwayland provides it…"* — one paragraph for five different situations; **after** (0.4.103, both nodes) `config: /etc/roomler/config.toml ([virtual_desktop_apps] enabled = true, 1 allowlisted)` · `apps supported: false` · `reason [no_session]: No active graphical login session on this host — nobody is at its screen — so there is no desktop to list windows on or launch into. Remote shell and file transfer still work. (no active graphical session — nobody is at this machine's screen)`. **Daemon arm unchanged** on the same node (AC3): `supported: true`, `sources: x11`, one root xterm. **GNOME Wayland host, live**: `supported: true` · `NOT listed: native Wayland windows…` · `missing tools: tmux …` — P2/P5 arms byte-for-byte, plus the new `config:` line. **The hello, from the server** (every online device): all 0.4.103 Linux and Windows devices advertise `["status","list","focus","launch"]`; both macOS rows `null`; the one 0.4.48 node `null` — `status` is on the wire fleet-wide, and each probed host's `list` matches its live state (the cluster nodes really have the Xvfb; the Wayland host really has a session, 1 day 16 h old). The **`disabled` arm** was not field-read: a throwaway `--config` in `/tmp` was attempted twice and the file landed **empty** both times — neither a `printf` with quotes nor a base64 payload survives Fleet RPC's argv re-split on a Linux target (the Windows quoting trap has a Linux cousin) — so the parser refused it at line 1 (`missing field server_url`), `read_if_present` answered *absent or unreadable — probing with the built-in default*, **wrote nothing**, and the device config was never touched (by design). The arm stays covered by `apps_caps_lock_status_and_follow_the_config`. |
| 2026-09-26 | ⛔ **AC10 release-time read, viewer half — BLOCKED, twice** | (1) **The hosted server has not been promoted**: `/health` answers `0.4.102`, and the served `RemoteControl-*.js` chunk has the P5 template strings (`is not installed on the agent host`, `Not listed —`, `missing_tools`) but **none of the P6 ones** (`carry no reason`, `open to see why`) — so the deployed viewer is still the one that drops `missing_tools` and renders a bare `supported:false` as a quiet desktop, whatever the agent now sends. (2) **No browser**: the shared Chrome extension reported no connected browser to the verifying session (`list_connected_browsers` → `[]`), and its last known account had zero devices; per the rules nothing was signed in and no other browser was selected. The pass, after a promote: the Apps dialog on the GNOME Wayland host shows the `tmux` warning; a headless host's dialog shows the `no_session` reason. AC10 is `[~]`. |
| 2026-09-25 | 🔎 **AC10 audit, fail-first on the current release (agent 0.4.102)** | Three reads, none needing a browser. (1) **The denominator, from the server** (every enrolled device's `capabilities.apps`, not an exec sweep): on 0.4.102 **every** Linux and Windows device advertised `list · focus · launch`; the two macOS rows advertised nothing (correct — no backend); one headless Linux node still on 0.4.48 advertised nothing — the "nobody at the screen" tier, whose reason exists nowhere a viewer can see it. (2) **`roomlerd apps-probe` over Fleet RPC**: three cluster nodes are Xvfb virtual desktops (`sources: x11`, `NOT listed: (nothing)`, `missing tools: (none)`, one root xterm each) — the Daemon tier, complete and honest; the GNOME Wayland host (Asahi) answered `sources: x11` / `NOT listed: native Wayland windows…` / `missing tools: tmux` — **the agent's half is right, and the viewer's parser drops that `tmux` line before it renders** (found by reading `parseAppsListReply`: it copies `sources` and `unlisted` only; #1179 never added the parse). The WSL node refuses Fleet RPC (`exec_enabled` off — the device-owned gate, working as designed) and stays an *advertised, unprobed* row. (3) **What a refusal says today**: `apps-probe` on a host with no desktop prints one generic paragraph that cannot distinguish *nobody logged in* from *no Xwayland* from *disabled*, because `discover()` returned `Option` and threw the distinction away; the reply the viewer gets is a bare `supported: false`, which the dialog renders as *"No windows reported"*. |
| 2026-09-25 | 🔧 **P6 built (PR [#1667](https://github.com/gjovanov/roomler-ai/pull/1667))** | `Unavailable {code, reason}` on every refusal, `status` on the hello, the parser fix, `wmctrl`-less session hosts stop advertising `list`, the probe loads the device config. Both new agent tests and the new viewer tests were **falsified before being trusted**: with the `unavailable` field removed from the reply the agent tests go red; against master's parser the `missing_tools` test goes red (the recorded runs are in the PR). ⚠️ A field read of the fix needs an agent release: the release-time pass is `apps-probe` printing `reason [no_session]` on a headless host and the Apps dialog showing the `tmux` warning on the GNOME Wayland host. ⚠️ **Lane trap, not this FR's bug:** `cargo test -p meshharbord --lib --features full` ICEs on rustc 1.95 (`annotate_snippets … StyledBuffer::replace`, query `check_mod_deathness` in `clipboard`) while *rendering* one of three pre-existing dead-code warnings in `clipboard.rs` — the same renderer ICE P1 hit, on a different diagnostic; CI's `--features full` lane never sees it because it runs `-A dead_code`. `--message-format=short` runs the identical compile and the tests; a `--message-format=short` check listed those three warnings as the **only** non-vendored diagnostics under `--features full`, none in this PR's files, and the same human-format check on the pre-P6 tree was A/B'd (see the PR). 🔎 **The review of #1667 found the "single source" claim false on a caps-cache MISS**: `cached_or_probed` returns the caps-probe *child's* struct wholesale there, and the child never loads the config — so `enabled = false` did not stop the hello advertising `list` on every release's first boot, or on any boot of a host with no hardware cell (never cached). `apps` is now assigned in `detect()` beside `rpc`, in the daemon; the child's struct carries none (a test locks it), which also takes the privilege-dropped `loginctl`/`wmctrl` walk out of the untrusted-driver child. The same review added a `discover_with(sess, probe)` seam with five tests over the refusal arms (each red with its arm reverted), the `tool_missing` reason now says the backend needs `wmctrl` to *find and manage the desktop* (launch is refused too — it used to go ahead blind), and `apps-probe` reads the config through FR-66's `read_if_present`, so a diagnostic can no longer write a `.prev` recovery as a side effect. |
| 2026-09-01 | ✅ **P5 shipped as the honesty the same session actually exposed** | Measuring for the refutation above turned up a real lie: **`apps supported: true` on a host with no `tmux`** — the panel offered the button and would have failed only once somebody clicked it, which is the same *empty-looks-like-fine* class as P2's unlisted sources. `Coverage.missing_tools` now names each absent helper with what it blocks and how to install it, probed **per call and never cached** (FR-45's rule — a host can gain `tmux` at any moment). Field-verified on Asahi **with both arms in one run**: `tmux` reported missing (ground truth: absent) *and* `xterm` NOT reported (ground truth: `/usr/bin/xterm`) — a probe that just reported everything would pass the first half and fail the second. ⚠️ `supported` deliberately stays **true**: listing and focusing genuinely work there, and collapsing a partial capability to `false` would remove a working feature — the boolean-vs-detail mistake P2 was built to fix. ⚠️ `wmctrl` is deliberately absent from the helper list — without it there IS no backend, so it must surface as a plain error, not as a footnote on a reply that otherwise reads like success. ⚠️ The probe resolves against the **daemon's** `PATH`, because `drop_to_std` changes uid from a `pre_exec` hook long after the environment was inherited; asking about the target user's login `PATH` would answer about an environment the child never gets. 🔑 Both new tests were **falsified before being trusted**: mutating `on_path` to always answer *present* fails them, and they pass again on revert. |
