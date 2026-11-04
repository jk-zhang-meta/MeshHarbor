# FR-61: Throwaway-OS install & verify matrix ("vmtest") — every method, every type, every OS, on demand

**Issue**: [#1199](https://github.com/jk-zhang-meta/MeshHarbor/issues/1199)
**Status**: built and field-verified — all five lanes green on every release since 0.4.48
(P0–P8, 2026-09-02..06); the regression-issue lifecycle made real and field-verified
2026-09-25 (P9); docs landed (P10). Open for the operator's call on AC10 and the close.
**Repos**: `meshharbor` (this spec, one Playwright spec, [`docs/vmtest.md`](../vmtest.md)),
`meshharbor-deploy` (orchestrator + lanes), `k8s-cluster-multi` (host capability)

## Goal

An on-demand harness that boots **lean throwaway VMs** on the fleet hosts, installs meshharbor in
each supported OS **via the served script AND via the release installer, per install type**, and
verifies three things per cell before destroying the VM:

1. **Remote desktop works** — a real browser session decodes frames from the freshly installed
   agent.
2. **The overlay works** — `meshharbor peers` sees an anchor node and `meshharbor ping` succeeds in
   both directions.
3. **`meshharbor-desktop` works across all its pages** — every view renders.

The product's acceptance bar is "it just works" on machines people actually have. Today that
bar has no harness: a fresh install on a clean OS is exercised only when a human happens to do
one.

## Evidence (why this exists)

- `installer-smoke.yml` covers exactly **2 cells** — Windows **perUser** MSI install/uninstall
  on a GitHub runner and a macOS `.pkg` install. The perMachine wxs is only *compiled* ("no
  install"). No Linux `.deb` install smoke, no perMachine/SystemContext install, no ARM, no
  Wayland, no enrollment, no remote desktop, no `meshharbor-desktop` — anywhere in CI.
- Every recent install-path defect shipped precisely because nothing installs the product the
  way users do, and was found by a **human** doing a field install:
  - FR-50 (#1083): the served installer could not know which server served it — found by
    FR-42's clean-box run.
  - FR-49 (#1084): a second org got no mesh while **five** surfaces reported healthy — found by
    enrolling demo devices by hand.
  - macOS "first-class" arc (2026-08-23): the install ran nothing, the pkg relocated itself
    into its own build directory, the companion could not start — five independent defects,
    none catchable by any lane that existed, found by a brand-new MacBook.
  - FR-53 (#1104): a recovered device warned about a crash loop for seven releases — found by
    pointing a camera at a screen.
- FR-51 (#1095) shipped ephemeral nodes and field-verified them against throwaway docker
  containers — the enrollment/reaping machinery this harness needs already exists and is live
  on prod (0.4.46).

## The matrix (v1)

| # | Lane (host) | Method | Types | RD check | Desktop check |
|---|---|---|---|---|---|
| 1 | **Win11 x86_64** — KVM on zeus, OVMF+swtpm, autounattend golden image, autologon + OpenSSH baked | `install.ps1` AND silent MSI | system (perMachine `ENABLE_SYSTEM_CONTEXT=1`) / attended (perMachine) / per-user (perUser MSI) | Playwright | CDP page-walk (5 views) + screenshots |
| 2 | Win11 **wizard smoke** | `meshharbor-setup` driven over CDP | one flavour (perUser) | – | wizard reaches Done; row deleted after |
| 3 | **Ubuntu 24.04 GNOME Wayland x86_64** — KVM on zeus/mars, cloud-init golden image, GDM autologin on Wayland | `install.sh` AND `.deb` via dpkg | system (`--system`; `drm_capture`+`uinput`) / per-user (user unit; `mutter_capture`) | Playwright | launch + `--view` walk + `virsh screendump` per view |
| 4 | **ARM Linux** — Ubuntu arm64 under QEMU **TCG** on zeus (the fleet is x86), AAVMF UEFI, headless + virtual-desktop mode | `install.sh` AND aarch64 `.deb` | system | Playwright, long timeouts | N/A — no aarch64 companion asset; assert the graceful skip |
| 5 | **macOS arm64** — tart VM on the operator's MacBook Pro (opt-in lane; auto-skipped when unreachable), TCC pre-granted in the golden image | `install.sh` (± `--daemon-token`) AND `installer -pkg` (± daemon marker) | per-user (LaunchAgent only) / system (marker ⇒ + root LaunchDaemon, two device rows) | Playwright | launch + screenshot walk |

Cells that cannot exist are recorded as N/A with the reason, not silently skipped:
`machine-attended` is a Windows-only concept (Linux = {system, per-user}; macOS = {agent-only,
agent+daemon}); ARM has no companion and no Windows; macOS has no Intel asset.

## Key design

### Per-cell flow

```
COW-clone golden image → boot → SSH in
→ install (method × type)            # script lanes use --no-enroll / -NoEnroll
→ meshharbord enroll --ephemeral        # reusable EphemeralEnrollment key, vmtest org
→ meshharbor config set auto_update false
→ service up
→ CHECKS: agent online (API) → peers/ping ↔ anchor → Playwright RD → desktop walk
→ TEARDOWN: graceful shutdown (ephemeral self-unenroll) → destroy
→ end of run: assert org device list back at baseline (reaper is the backstop)
```

### What each repo owns

- **k8s-cluster-multi** — `playbooks/15-vmtest.yml` (opt-in, NOT in `site.yml`, like 16) +
  `roles/vmtest-host`: qemu-system-aarch64 + AAVMF + OVMF + swtpm, a `vmtest-net` NAT network
  on its own bridge (the `-i virbrX -j ACCEPT` HOST_FW_INPUT rule ships with it — the
  documented DHCP-hang foot-gun), `/var/lib/libvirt/vmtest` storage with a disk preflight, and
  cached images (noble amd64+arm64 cloud images, virtio-win ISO, Win11 Enterprise Eval ISO).
- **meshharbor-deploy** — `vmtest/`: `vmtest.sh` (`bake|run|destroy|report|clean`, filters
  `--lane --method --type --host --keep`), per-lane bake+run scripts, guest drivers, dockerized
  Playwright runner, report in the e2e-nightly shape (`~/vmtest/<stamp>/`, `LATEST`,
  `expected-failures.txt` diff, isolated re-run for unexpected failures, GitHub issue on
  regression).
- **meshharbor** — `ui/e2e/vmtest-remote.spec.ts`, modeled on
  `remote-session-smoke.spec.ts` with exact-name agent selection (`E2E_AGENT_NAME`) so multiple
  live VMs cannot cross-match.

### The facts the design rests on (anchors verified against master)

- **Install scripts**: `scripts/install.sh` — `--role daemon|tunnel --server --token --name
  --system --no-enroll --download-only --desktop`; per-user default (`systemctl --user`,
  `meshharbor.service`) vs `--system` (`/etc/meshharbor/config.toml` + `meshharbord.service`); macOS
  `--daemon-token` writes the `/etc/meshharbor/enable-daemon` marker before the pkg (two rows by
  construction). `scripts/install.ps1` — `-Role daemon-user|daemon-machine|daemon-system
  -Token -Name -NoEnroll -AllowElevated`; `daemon-user` **throws in an elevated shell** without
  `-AllowElevated`; `daemon-system` adds `ENABLE_SYSTEM_CONTEXT=1` and enrolls
  `--machine-global`. Both carry the FR-50 serve-time server-URL rewrite, so the script lane
  must fetch from the server under test, never from the repo.
- **MSI**: two products (perUser task-autostart, `agents/meshharbord/wix/main.wxs`; perMachine SCM
  service, `agents/meshharbord/wix-perMachine/main.wxs`); the third type is the property flip
  `ENABLE_SYSTEM_CONTEXT=1` — the **only** public property (`wix-perMachine/main.wxs:395`).
  Enrollment is always post-MSI (`meshharbord enroll`, `--machine-global` for the machine
  flavours); the perMachine service auto-starts at install, so the ephemeral enroll may need a
  stop-enroll-start dance (`enroll --ephemeral` refuses if a config exists —
  `agents/meshharbord/src/main.rs:96-102`).
- **Consent**: `resolve_session_authz` (`crates/api/src/ws/remote_control.rs:1708`) resolves
  the device **owner** to `owner_consent_mode()` = Auto unless `prompt_owner`; the agent-local
  `auto_grant_session` defaults **true** at enroll. Controller = the enrolling admin ⇒ RD
  checks run with zero prompts, by design, not by weakening anything.
- **Release assets**: aarch64 Linux `.deb`/`.tar.gz` exist (no `ffmpeg-encoder` — SW encode
  only); there is **no aarch64 `meshharbor-desktop`** and **no Intel macOS** asset; the macOS
  `.pkg` is `aarch64-apple-darwin` only.
- **meshharbor-desktop**: 5 views (`overview|devices|tunnels|settings|onboarding`,
  `agents/meshharbor-desktop/src/front/app.js`), `--view=` deep-link only fires via the
  single-instance second launch; Tauri ⇒ on Windows the WebView2 runtime honours
  `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=<p>` from the environment, so
  the page-walk is CDP-driven DOM assertion; Linux WebKitGTK has no CDP ⇒ `virsh screendump`
  per view + LocalAPI state instead.
- **Verification CLI**: `meshharbor peers --json`, `meshharbor ping <target> --json` (failure ⇒
  exit 1), `meshharbor status --json` (`agents/meshharbor-cli/src/cli.rs`).
- **Ephemeral (FR-51)**: reusable keys gated by org `ephemeral_keys_enabled` (re-checked per
  use ⇒ flipping it off is class-wide revocation); reaper
  `MESHHARBOR__RC__EPHEMERAL_REAPER_ENABLED` already on in prod; graceful shutdown self-unenrolls.
  The wizard smoke cannot use an ephemeral key (wrong JWT audience for plain `enroll`) — it
  mints a single-use standard enrollment token and deletes its row afterwards.

### Safety rails

- **jupiter carries prod storage** (mongo/minio/meshharbor2 PVCs) — vmtest schedules on zeus (and
  mars for overflow); jupiter only in an announced window.
- **Sequential by default** — one VM per host at a time (≤8 GB peak), so the k8s VMs should not
  need shrinking; a capacity audit prints before every run, and the shrink runbook
  (`virsh setmem` + the `group_vars/all.yml vms:` mirror edit) exists but executes only on a
  measured shortfall.
- **Prod isolation** — a dedicated vmtest org; ephemeral rows only (plus one permanent anchor
  with `auto_update=false`); nothing in the prod fleet org is touched; the reaper is already
  prod-verified (FR-51 AC5: permanent rows survive).
- All host capability is **opt-in** (playbook outside `site.yml`; nothing scheduled; no
  standing VMs between runs unless `--keep`).

## Phases

| Phase | What | Kill switch / rollback |
|---|---|---|
| P0 | This spec + ledger row + issue | — |
| P1 | k8s-cluster-multi: `vmtest-host` role + playbook 15, capacity audit, shrink runbook | playbook is opt-in; role removal reverts the host |
| P2 | meshharbor-deploy: `vmtest.sh` orchestrator + Ubuntu GUI Wayland lane; vmtest org + anchor + ephemeral key | org `ephemeral_keys_enabled=false` revokes all keys; anchor container stop |
| P3 | meshharbor: `vmtest-remote.spec.ts` (RD check, name-filtered) | spec is env-gated, skips without `E2E_AGENT_NAME` |
| P4 | Win11 lane: golden image bake + 3 types × 2 methods + wizard smoke + CDP desktop walk | delete image + overlays |
| P5 | ARM lane (TCG on zeus): system × 2 methods; RD best-effort behind expected-failures | delete image + overlays |
| P6 | macOS lane (tart on the MacBook, opt-in): 2 types × 2 methods | `tart delete`; lane auto-skips when host absent |
| P7 | **Run and tweak** — every supported cell to green on the live fleet; fail-first evidence per cell class; Result comment with the matrix | — |
| P8 | Repeatable skill (`vmtest`) — written after P7 proves the flow | — |
| P9 | **Regression-issue lifecycle** (`meshharbor-deploy` #12, 2026-09-25) — the isolated re-run the README had described since P2 but nothing performed; ONE issue per condition (`lane/method/type#check`, any host), a comment on repeat, closed by the first green run (the legacy per-run issues drain the same way); unreached checks record `NA`, not `FAIL`; `vmtest.sh triage --run-dir` re-evaluates a finished run without VMs | `VMTEST_RERUN=0` skips the re-run; `VMTEST_FILE_ISSUES=0` makes the lifecycle a logged dry run |
| P10 | **Docs** — [`docs/vmtest.md`](../vmtest.md) in the house style + a `docs/README.md` row + a `testing.md` pointer | — |

## Acceptance criteria

- [x] AC1 — Ubuntu 4/4 GREEN (script + `.deb` × system + per-user; Wayland session verified
  `seat0 ... wayland`; per-user via netstack). Field-verified prod 0.4.48, 2026-09-02.
- [x] AC2 — Win11 6/6 GREEN (`install.ps1` daemon-system/machine/user AND silent perMachine/
  perUser MSI incl. `ENABLE_SYSTEM_CONTEXT=1`; SystemContext overlay = two meshharbord, session-0
  supervisor + session-1 worker; per-user via netstack). Field-verified 0.4.48, 2026-09-02.
- [x] AC3 — the wizard smoke walks Welcome→Server→Token→Install→**Done** over WebView2 CDP,
  enrols a real device and deletes its (non-ephemeral) row. Unblocked by publishing
  `setup-v0.4.48` — see the field log for why no wizard release could be cut before.
- [x] AC4 — ARM Linux GREEN 2/2 (script + aarch64 `.deb`, system): install / enroll / overlay
  (`ping anchor ~4 ms`); RD even PASSES under TCG (virtual-desktop Xvfb + SW encode). Desktop is
  N/A (no aarch64 companion) and the graceful skip is asserted. Field-verified 0.4.48, 2026-09-02.

- [x] AC5 — macOS GREEN 4/4 on throwaway **tart** VMs (Apple-silicon MacBook, reached from mars
  over meshharbor's OWN mesh): served `install.sh` AND `.pkg`, agent-only AND agent+daemon
  (marker on/off). The `system` cells MESH from the VM (`self=100.65.20.x`, anchor ping ok).
  RD + the per-user row's liveness are N/A-by-construction headlessly (Aqua session + TCC).
- [x] AC6 — RD asserts frames FLOW and ADVANCE (getStats `framesDecoded` / the composable's live
  fps hook, with a transport-agnostic canvas-pixel-change fallback for the DataChannel/VP9-444
  path that has no `<video>`). Verified on Ubuntu + Windows (VP9-444, direct, 29 fps).
- [x] AC7 — all 5 meshharbor-desktop views walked; Windows asserts real DOM per view over WebView2
  CDP; Linux uses `virsh screendump` per view (pairwise-distinct). Verified.
- [x] AC8 — teardown leaves the org at baseline (graceful self-unenroll + reaper backstop
  observed; `count ≤ baseline` accepts the reaper cleaning older leftovers); k8s untouched
  (`kubectl get nodes` + prod `/health` green across every run).
- [x] AC9 — the regression-issue mechanism files **one issue per condition**
  (`lane/method/type#check`), only after an **isolated re-run** confirms the failure; a repeat
  comments on the open issue; the first green run closes it — and drains the legacy per-run
  issues once every condition they list is green. Field-verified 2026-09-25 on
  `ubuntu/script/system@zeus` with an induced enroll refusal, fail-first: master filed #1618
  and, eight minutes later, its duplicate #1620 (one per run, no re-run, nothing closing
  either); the fix (`meshharbor-deploy` #12) filed **#1623** once (run A, after the re-run),
  commented on it (run B), and the green run C retired #1623, #1620 and #1618 with a comment
  naming the run. Runs and rows in the field log.
- [~] AC10 — fail-first evidence per cell class (P7), each shown failing before its fix or
  expectation, with the run id and the issue the mechanism filed (the table in the field log,
  2026-09-25). **Met** for perMachine SystemContext (`win11/script/system` — three PowerShell
  defects, #1215/#1216), Wayland RD (`ubuntu/*#rd` — cookie auth + the DataChannel transport,
  #1210/#1212; the RTP-shaped oracle blind to that transport, #1295/#1298/#1300), ARM install
  (`libasound2` left uninstalled by the aarch64 `.deb` ⇒ `meshharbord` rc=127, #1220; the
  dpkg-lock race, #1403) and the wizard (no `setup-v*` release, then CDP selectors + clock skew,
  #1224–#1227). **Not met as worded** for the x86 Linux `.deb` install:
  `ubuntu/installer/*#install` PASSED on its first recorded run (`20260902-012127`) and never
  needed a fix, so there is no "before" to show; the `.deb` cells' first red was the per-user
  overlay (netstack, #1214), and the only `.deb` *install-check* fail-firsts on record are the
  ARM ones. Producing an x86 `.deb` install failure would mean shipping a broken `.deb` —
  whether the class-level evidence satisfies this criterion is the operator's call.
- [x] AC11 — invocable as one command from the dev box via mars (`vmtest.sh run --lane/--method/
  --type`, `--keep`); the `vmtest` skill documents it.
- [x] AC12 — docs: [`docs/vmtest.md`](../vmtest.md) in the house style (mermaid, tables,
  callouts, `file:line` anchors), a row in `docs/README.md`'s index, and `testing.md` pointing
  at it. Landed with the 2026-09-25 spec PR, #1648.

## Open decisions

1. Win11 image: swtpm-backed TPM2 vs LabConfig registry bypasses — ship both, prefer swtpm,
   keep the bypasses as belt-and-braces (decided in P4 by what the bake proves).
2. DXGI Desktop Duplication on virtio-gpu DOD vs the agent's GDI fallback — whichever the field
   shows; the check only requires frames, and the harness records which path carried them.
3. RD input round-trip assertion (inject via session, observe in-VM) — v2; v1 is frames-only.
4. Weekly cron — one line once the matrix is stable; v1 is on-demand only.

## Out of scope

- Windows-on-ARM (no asset), Intel macOS (no asset).
- Full wizard automation on Linux/macOS (WebKitGTK/WKWebView expose no CDP).
- Portal/consent-prompt UI automation on Wayland — the portal is attended **by design**; the
  Wayland cells use the `drm_capture`/`uinput` (system) and `mutter_capture` (per-user) paths.
- Corp-network topologies (VPN/symmetric NAT) — this FR verifies *install × type × OS*; network
  topology matrices remain the fleet's job (FR-33 et al.).
- Publishing the harness for third parties (it assumes the fleet's layout).

## Field-verification log

**2026-09-02, prod 0.4.48 — ALL FIVE LANES GREEN: 18 cells (Ubuntu 4/4, Win11 6/6 + the wizard
smoke, ARM 2/2, macOS 4/4).** The harness was
built and driven to green on the live fleet; the run-and-tweak phase found and fixed **27 field
bugs**, each shown failing before its fix. Highlights (full detail in the memory + the issue's
step-log comments):

- **Ubuntu** (script + `.deb` × system + per-user): install / enroll / overlay (`meshharbor ping`
  anchor round-trip ~1–2 ms) / Wayland (`seat0 ... wayland`) / RD (VP9-444 direct 29 fps, real
  GNOME desktop — DRM capture in a virtio-gpu KVM guest) / meshharbor-desktop (5 views).
- **Win11** (install.ps1 + MSI × system/attended/user): install / enroll / SystemContext overlay
  (two meshharbord — session-0 SYSTEM supervisor + session-1 worker) / RD / desktop (5 views over
  WebView2 CDP). Golden image bakes unattended (autounattend + OVMF + swtpm + virtio).

Load-bearing bugs (each cost a real debug cycle): an ephemeral daemon **unenrolls itself on
SIGTERM** so a post-enroll restart deleted the device; the configless crash-loop trips systemd's
**start rate-limit**; libvirt's default IP source is unreliable (needs `--source arp`); a bash
`${2:-{}}` default **corrupted every JSON API body**; `meshharbor status` overlay address is
top-level `.overlay_ip`; a multi-cell run **ran only the first cell** (ssh ate the loop pipe);
sessions are **cookie-only** (RD spec landed on /login); a SW-encode agent streams **VP9-444 over
a DataChannel → a canvas, not `<video>`** (transport-agnostic frame oracle); on Windows,
`$ErrorActionPreference='Stop'` turns native stderr into a terminating error, `wait_guest_ssh`'s
`true` probe doesn't exist in PowerShell, and non-ASCII in a `.ps1` breaks the parse.

**Two product findings surfaced by the harness (each worth its own FR):**
1. **The test org was on the FREE plan — a 3-device cap** (`crates/db/src/models/tenant.rs`).
   Anchor + un-reaped orphans hit it and every new enroll got `403 "Device limit reached"` — a
   *silent* matrix-killer that reads like an overlay bug.
2. **Per-user overlay is broken out of the box on BOTH OSes** — an unprivileged per-user daemon
   can't create a WireGuard TUN, and a vanilla per-user install doesn't auto-configure the
   userspace netstack (`MESHHARBORD_OVERLAY_NETSTACK_SOCKS`), so `overlay_mode=tun` never gets an
   address. The installer should set netstack up for a per-user role.

**The last two lanes, and what they cost:**

- **Win11 wizard.** No `setup-v*` release existed, so `/api/setup/windows` 404'd. The cause was
  structural rather than a missing tag: the wizard release is all-or-nothing and its macOS job
  REQUIRES Apple credentials that do not exist yet (FR-7 enrolment pending), so it failed and
  took Linux + Windows down with it. Fixed with an explicit default-false `skip_macos` input
  (#1222), published `setup-v0.4.48`, and the cell now walks the wizard to **Done**, enrols a
  real device and deletes its row. Two harness bugs fell out: the walker guessed selectors (it
  now drives the wizard's own stable ids), and a cloned Win11 guest boots **~3 h ahead of UTC**,
  so a freshly minted 10-minute enrollment token was rejected as "already expired" — a clock bug
  wearing an auth error's clothes.
- **macOS.** Runs on **throwaway `tart` VMs on the operator's Apple-silicon Mac**, driven from
  mars over **meshharbor's own mesh** (`meshharbor ssh` — the Mac has Remote Login off and no public
  IP, so the harness dogfoods the product). It cannot move to the fleet: all three hosts are AMD,
  macOS may only be virtualised on Apple silicon, and meshharbor ships **no x86_64 macOS artifact**,
  so an x86 VM would have nothing to install even if it booted. Four environment defects were
  found and fixed — `tart stop` loses the injected SSH key (shut down from inside), the vmnet
  resolver times out (pin DNS in the golden), the daemon bundle was renamed (resolve it), and the
  cell asked the server about a VM it had already destroyed. Remote desktop and the per-user
  row's liveness stay N/A headlessly: both need an Aqua session plus a TCC grant, which one human
  action in the golden unlocks — the same "attended by design" shape as the Wayland portal.

Also fixed here, and worth carrying: **`curl … | bash` reports BASH's status**, so a failed fetch
(no DNS) still read as `install PASS` having installed nothing — the standing "never branch on a
piped exit status" rule, recurring in a new place.

**2026-09-04 → 2026-09-24 — re-runs on 0.4.61, 0.4.67, 0.4.69, 0.4.75, 0.4.82 (issue step log):
17/17 green each time; no product regression across seven releases.** What broke was the harness
(the RTP-shaped RD oracle, guest DNS/dpkg races, Playwright drift, a stale clone) and each is a
trap in [`docs/vmtest.md`](../vmtest.md). The FR-51 lifecycle joined as a standing cell
(`ephem/lifecycle/both`, `meshharbor-deploy` #7).

**2026-09-25 — AC9: the regression-issue lifecycle, made real and field-verified
(`meshharbor-deploy` #12).** Two findings first, both visible only by reading what the mechanism
had actually done rather than what its comments said:

1. **The isolated re-run never existed.** `vmtest.sh`'s header, `README.md` and
   `vmtest.env.example` all described "one isolated re-run, then a GitHub issue" from P2 on;
   `finish_run` diffed against `expected-failures.txt` and called `gh issue create`
   unconditionally. The re-runs in the 09-04/09-05/09-06 step-log entries were done by hand
   (`fr61-rerun*` driver dirs on the orchestrator). The mechanism *did* fire — 31 issues,
   09-02..09-10 — but **one per RUN**: #1224–#1227 are the same `win11/wizard/user#install` four
   times inside an hour, and none was ever de-duplicated or closed by anything but the 09-24 bulk
   sweep. AC9's old text ("not yet observed firing") was stale; the real gap was "fires once per
   condition and closes itself".
2. **Unreached checks were recorded as FAIL.** A refused enroll produced `enroll FAIL`,
   `overlay FAIL "no verdict"`, `wayland FAIL "no verdict"` **and** a bare-cell
   `FAIL "cell script rc=1"` — one root cause, four FAIL rows; the bare row landed on *every*
   failing cell because its guard grepped `<cell><TAB>`, which never matches a `<cell>#check`
   row. Under per-condition keying that is four issues. Now the lift stops at the first FAIL or
   the first missing verdict (`lib.sh lift_verdicts`) and later checks record `NA "not
   reached"`; the bare row lands only when the cell has no FAIL row of its own.

**The fail-first**, on `ubuntu/script/system@zeus` with an induced, harmless failure — a
deliberately invalid ephemeral key, so `meshharbord enroll` is refused by the server and no device
row ever exists (org at baseline 1 throughout). The current-master code ran from a separate
clone, the fix from the PR branch, each with its own `VMTEST_HOME`; nothing touched the shared
orchestrator checkout:

| run | code | result | what the mechanism did |
|---|---|---|---|
| `20260925-110253` | master (`623fe58`) | `FAIL pass=4 fail=5 na=1` — enroll rc=1, overlay + wayland "no verdict", bare cell | **#1618** created at once, no re-run |
| `20260925-111117` | master | same | **#1620** created — a duplicate of #1618 eight minutes later; one issue per run, nothing closes either |
| `20260925-111956` (A) | PR #12 (`e5b744d`) | main `FAIL pass=4 fail=2 na=3`: enroll rc=1, overlay + wayland **NA "not reached"**, no bare row; isolated re-run (11:28→11:36) identical ⇒ `unexpected='…#enroll' flaky=''` | **#1623** `vmtest: unexpected failure in ubuntu/script/system#enroll` created — ONE issue for one root cause; #1618/#1620 left open ("RED in this run") |
| `20260925-113642` (B) | PR #12 | identical to A (main + isolated re-run) | a **comment** on #1623, no new issue; open vmtest issues still exactly three (#1618, #1620, #1623) |
| `20260925-115327` (C) | PR #12, valid key | `PASS pass=8 fail=0 na=0` — enroll, overlay (`self=100.65.20.1`, anchor 2 ms), wayland, **RD** (frames decoded, advancing), desktop (5 views); org back at baseline 1; no VM left on zeus | close-on-green retired **#1623**, then **#1620 and #1618** (every condition each lists went green), each with a comment naming the run; zero open `vmtest:` issues afterwards |

Dry `triage` runs before the field test (copied run dirs, `VMTEST_FILE_ISSUES=0`): the
2026-09-02 ARM failure run → six "would create" (its archived rows still carry the cascade
FAILs) and "#1618 stays open: UNSEEN"; the last green sweep (`20260924-202800`) → "would close
#1618 (green: all four conditions)"; the before-run itself → "#1618 stays open: RED".

**AC10 — the fail-first per cell class, reconstructed from the run archive and the issues the
mechanism filed** (run ids are directories on the orchestrator; every FAIL row quoted is in that
run's `results.tsv`):

| class | first red | fix | first green |
|---|---|---|---|
| perMachine **SystemContext** (`win11/script/system`: `install.ps1 -Role daemon-system` ⇒ `ENABLE_SYSTEM_CONTEXT=1`) | `20260902-021940` `#enroll FAIL` with an **empty** detail (`$ErrorActionPreference='Stop'` turned meshharbord's stderr into a terminating error) + `#overlay` no verdict → #1215; `20260902-023040` `#install FAIL no verdict` (non-ASCII broke the `.ps1` parse; the `true` SSH probe) → #1216 | the three PowerShell fixes (03:01 step-log entry) | `20260902-024606` — all PASS, `self=100.65.20.3`. The MSI SystemContext cell (`win11/installer/system`) passed on its first run |
| **Wayland RD** (`ubuntu/*#rd`) | `20260902-002533` `#rd FAIL` → #1210; `20260902-004405` → #1212 (cookie-only sessions #1211; the DataChannel→canvas transport #1213). Again `20260904-000906` on all four Ubuntu cells → #1295/#1298/#1300 (the RTP-shaped oracle blind to that transport, #1297; the static-desktop keepalive, #1301) | as cited | `20260902-010001`; `20260904-010310` / `014606` / `015150` |
| **ARM install** | `20260902-034419` `arm/{script,installer}/system#enroll FAIL meshharbord enroll --ephemeral rc=127` — guest.log: `meshharbord depends on libasound2; however: Package libasound2 is not installed` (the aarch64 `.deb` left unconfigured; rc=127 is the loader failing on `libasound.so.2`) → #1220. `20260905-202405` `arm/installer/system#install FAIL dpkg/apt install failed` (the `unattended-upgrades` lock race) → #1403 | the ALSA runtime dependency in the guest driver; apt timers stopped + masked, `DPkg::Lock::Timeout=300` | `20260902-041405`; `20260905-205517` |
| **wizard** (`win11/wizard/user`) | `20260902-030033` `#install FAIL wizard fetch/launch failed` (no `setup-v*` release — `/api/setup/windows` 404), recorded as an expected failure; after `setup-v0.4.48`: `20260902-083823` `#install FAIL wizard CDP walk failed` + `#enroll FAIL no device row` → #1224, then `084120` → #1225, `084413` → #1226, → #1227 (guessed selectors; a guest clock ~3 h ahead of UTC rejecting a fresh token) | #1222 (`skip_macos`), the wizard's own stable ids, a `w32time` resync | `20260902-084901` `wizard walked Welcome→Done over CDP` |
| Linux **`.deb`** install (`ubuntu/installer/*`) | **no install-check red exists**: `#install PASS .deb installed (x86_64)` on the first recorded run, `20260902-012127`, for both types. The cells' first red was `ubuntu/installer/user#overlay FAIL no overlay self address within 90s` (a per-user daemon cannot create a TUN — the netstack finding) in that same run → #1214 | `MESHHARBORD_OVERLAY_NETSTACK_SOCKS` for the per-user role | `20260902-015346` |
