# FR-8: Claude session restore after reboot — `crestore` (WT tabs / VS Code terminals)

**Status: SHIPPED + field-verified (retrospective).** Planned + implemented 2026-08-18 (tracker, WT target, phases 1–3), extended 2026-08-26 (VS Code target, phase 4). This is **dev-box tooling**: it lives in `C:\Users\goran\.claude\session-restore\` on the dev box (neo16), not in this repo's source tree — documented here per the FR workflow because every meshharbor (and lgr/pcon/…) working session runs through it.

## Problem / Goal

Development runs many parallel Claude Code sessions, each in its own pwsh terminal (VS Code integrated terminals and standalone), across several project folders and worktrees (`meshharbor`, `lgr`, `pcon`, `ut-ki-portal`, `pcon_classic`, …). A Windows restart kills every terminal; getting back to work meant manually reopening each terminal, cd'ing to the right folder, and finding + `claude --resume`-ing the right session — a dozen manual round-trips per reboot.

**Goal:** one command (`crestore`) that knows which sessions were open at shutdown and restores them all — each in its own terminal, in its original working directory, with the original session resumed and the original launch flags (`--dangerously-skip-permissions`, `--model`, …) replayed — for **any project folder**, into either **Windows Terminal tabs** or **VS Code integrated terminals**. Resuming loads only the transcript, so it costs no tokens until a prompt is sent.

## Key design

Two parts + two spawn targets, all under `~/.claude/session-restore/`:

### 1. Tracker (`hook.ps1`)

`SessionStart`/`SessionEnd` hooks in the **user-level** `~/.claude/settings.json` (so every project folder is covered) maintain one JSON per session in `registry/`: session id, cwd, transcript path, start time, and the owning claude **PID + full command line** (found by walking the hook's parent-process chain). A clean `SessionEnd` stamps `ended_at`; a reboot kills processes without the hook ever firing — **an open entry with no clean end is precisely a restore candidate**. `/clear`/fork supersede the prior entry with the same PID; entries GC after 14 days; the hook always exits 0 (a broken hook must never break a session).

- ⚠️ Claude Code hooks on this machine execute through **Git Bash**, not PowerShell — the settings command uses forward slashes (`pwsh -NoProfile -NoLogo -File C:/Users/goran/.claude/session-restore/hook.ps1`; bash eats backslashes in unquoted words), and the parent walk treats `bash`/`sh` as walkable shell wrappers.
- Field-proven: ✕-closing a terminal **does** fire `SessionEnd` (`reason: other`); only hard kills (reboot) leave entries open. Headless `-p` runs and subagent hook invocations are filtered out.

### 2. Restore CLI (`Restore-ClaudeSessions.ps1`, alias `crestore` in `$PROFILE`)

Candidates = open registry entries with transcript mtime within `-MaxAgeHours` (default 72), an existing cwd, and a recorded PID that is **not** alive (never double-resume a live session). Numbered picker (Enter = all), positional folder filter (`crestore lgr`), `-List`, `-All`, `-DryRun`, `-Prune`, and `-Scan` — a bootstrap mode inferring sessions from transcript mtimes for sessions predating the hooks (flags <5-min-fresh files "may still be running" and warns when claude processes exist, because scan cannot distinguish idle-open from killed). Titles derive from the transcript's first real user message (these transcripts carry no `"type":"summary"` records). Launch-flag replay is **whitelist-only** (`--dangerously-skip-permissions`, `--model`, `--permission-mode`, `--add-dir`) so positional prompts and one-shot flags are never replayed.

### 3. Spawn targets

- **`wt` (default):** one `wt -w claude-restore nt -d <cwd> --title <t> pwsh -NoLogo -NoExit -Command "claude … --resume <id>"` invocation per tab (per-tab invocations dodge wt's `;` command-separator escaping entirely).
- **`-Target vscode`:** writes one **pending file** per session to `vscode-pending/` (15-min expiry) and runs `code <folder>` per distinct cwd. A **local unpacked VS Code extension** (`goran.claude-session-restore`, source `vscode-ext/`, auto-synced into `~/.vscode/extensions/` by the script) consumes pendings **on window startup and via an fs-watcher** — run crestore before or after opening VS Code, both orders work — **claiming each file by delete**, so with N windows open every session spawns exactly once; the integrated terminal opens in the session's cwd and sends the resume command. Chosen over the marketplace "Restore Terminals" extension deliberately: no JSONC `settings.json` mutation, no re-spawn on every window open, one-shot by construction, zero third-party dependency.
- `$env:CRESTORE_TARGET='vscode'` makes VS Code the default target; `-InstallStartup` registers an optional delayed logon task (deliberately NOT enabled by default — restore stays a conscious action).

## Phase / status table

| Phase | What | Kill switch | Status |
|---|---|---|---|
| 1 | Tracker hooks + registry | remove the `hooks` block from `~/.claude/settings.json` | SHIPPED 2026-08-18 |
| 2 | Restore CLI + `crestore` alias + `-Scan` bootstrap | manual command; `-Prune` marks all open entries ended | SHIPPED 2026-08-18 |
| 3 | Logon task (`-InstallStartup`) | `-UninstallStartup` | SHIPPED 2026-08-18, default OFF |
| 4 | VS Code target (pending queue + local extension) | delete `~\.vscode\extensions\goran.claude-session-restore-0.1.0`; stale pendings self-expire in 15 min | SHIPPED 2026-08-26 |
| 5 | Per-session effort (`-Effort`, default `max`) | `-Effort none` (omit the flag) / `-Effort inherit` (keep each session's original) / `$env:CRESTORE_EFFORT` | SHIPPED 2026-08-28 |

## Acceptance criteria

- [x] Sessions from **any** folder are tracked (user-level hooks) and restored into the right cwd with the right session id
- [x] Killed-by-reboot sessions are offered; cleanly exited / ✕-closed sessions are not; live sessions are never double-resumed (PID liveness check)
- [x] Original launch flags replayed per session (whitelist); resume costs no tokens until a prompt is sent
- [x] Every restored session starts at a chosen effort level (`-Effort`, default `max`), overridable per run and per environment, with `inherit`/`none` escape hatches — and an unknown level is a hard error rather than a silent downgrade
- [x] WT target: one tab per session in a named `claude-restore` window
- [x] VS Code target: terminals appear in the right window whether `crestore` runs before or after VS Code opens; exactly-once across multiple open windows
- [x] `-Scan` bootstraps sessions from before hook installation, flagging possibly-live ones
- [x] Silent failure modes are logged (`hook.log`, `vscode-ext.log`) and never break a session

## Open decisions

1. Auto-restore at logon (`-InstallStartup` + `-All`, no picker) — available but deliberately not default; revisit if the picker step ever feels like friction.
2. WSL-side claude sessions — untracked today (hooks fire, but spawn targets are Windows-side); add a `wsl.exe -d <distro>` spawn path if WSL sessions become routine.

## Out of scope

- Reconstructing VS Code window *layout* beyond one window per distinct folder.
- Original-terminal-host fidelity: a session that lived in a VS Code terminal may be restored into WT and vice versa — user's choice via `-Target`.
- Restoring non-claude terminal state (running builds, ssh sessions, tmux — tmux already survives on the fleet side).

## Effort (phase 5, 2026-08-28)

`-Effort <low|medium|high|xhigh|max|inherit|none>`, default **`max`**, env default `CRESTORE_EFFORT`. Restored sessions carry `claude --effort <level> --resume <id>` on both targets. `inherit` replays the level the session was originally launched with (omitting the flag if it had none); `none` never passes it. `--effort` is also added to the replay whitelist, and `Build-ResumeCommand` **strips any replayed `--effort` before appending the resolved one**, so a session can never carry the flag twice. `Test-EffortSupported` probes `claude --help` once per run and degrades to omitting the flag on a CLI too old to have it.

⚠️ **The ValidateSet is a security-of-intent control, not decoration**: claude itself only *warns* on an unknown `--effort` value (`Unknown --effort value 'bogus' — ignoring it and using the default effort`) and proceeds at the default. A typo would therefore silently restore a whole fleet of sessions at the wrong level; the script refuses instead.

⚠️ **Known measurement limit — the flag's effect is verified for plumbing, not for the TUI.** Non-interactive paths (`-p`, and a positional prompt, both `entrypoint: sdk`/one-shot) record `"effort":"max"` on their assistant turns **regardless of the requested level** — a `--effort low` one-shot still recorded `max`. Interactive sessions do record real per-session levels (this repo's transcripts carry `high`/`medium`/`xhigh`/`max`), but effort is written **only on assistant turns** — there is no session-state record — so confirming a restored TUI session's level requires sending it a prompt, which cannot be automated without injecting keystrokes into a window (unacceptable with ~20 live sessions on screen). Confirm by eye in a restored tab: `/effort` reports the current level.

## Field-verification log

- **2026-08-18 — hook unit tests** (fake stdin events): SessionStart writes a full entry; SessionEnd stamps `ended_at`+reason; subagent events ignored; malformed input logged and swallowed (exit 0).
- **2026-08-18 — WT E2E**: registry-driven restore spawned a `claude-restore` WT tab, cd'ed to `C:\dev\pcon_classic`, resumed session `cbbd0508` **with `--dangerously-skip-permissions` replayed**; the hook inside the spawned session re-registered it within seconds (source `resume`, real PID, real cmdline). Closing the tab later stamped a clean end (`reason: other`).
- **2026-08-18 → 08-26 — tracker soak**: 8 days unattended across 5+ project folders; `/resume` switches recorded as `end_reason: resume`; live sessions carry fresh PID+cmdline; registry GC held.
- **2026-08-26 — VS Code E2E**: with the target window already open, a written pending file was consumed by the extension's **watcher within ~5 s** (`spawning (watch): "watch-e2e pcon_classic"`); the integrated terminal spawned in the right cwd, resumed `b072f5e0`, and the registry flipped to open with the new PID and the replayed flag. Exactly-once held with 4 extension hosts live (claim-by-delete). Unpacked-folder extensions load fine (VS Code Aug 2026) but are **scanned only at app start** — first install needs a VS Code restart.
- **2026-08-26 — dry-runs both targets** over the real registry: 11 correct per-session commands across `lgr` / `mh` / `ut-ki-portal`; sessions without a recorded cmdline correctly fall back to plain `claude --resume <id>`; live sessions excluded; sub-5-min scan hits flagged `[!]`.
- **2026-08-28 — effort option (phase 5)**: seven modes exercised by dry-run across the real registry on both targets — default `max`, explicit `high`, `none` (flag absent), `inherit` (absent when the session recorded none), `$env:CRESTORE_EFFORT=xhigh`, VS Code queue carrying the flag, and an invalid level correctly rejected by the ValidateSet. `claude --effort max --resume <bad-id>` fails on the *session id*, proving the flag composes with `--resume`. Dead ends recorded above: print-mode/one-shot transcripts pin `effort: max`, so they cannot serve as a probe; the CLI ships as a 253 MB compiled binary, so the wiring cannot be read from a bundle; and no session-state effort record exists to read without prompting the session.
- **Gotchas banked** (memory `reference_claude_session_restore.md`): Git-Bash hook execution → forward-slash paths; claude ≥2.1.223 **cross-directory resume** records the *invoking* cwd in the hook event (transcript stays in the original project dir) — harmless for the mechanism (restore always cd's first), confusing for forensics; PS local `$list` silently collides with a `[switch]$List` parameter; a silent `continue` in the extension's consume loop hid an E2E failure for an hour — every drop now logs.
