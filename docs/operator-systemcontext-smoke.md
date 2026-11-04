# Operator checklist — verifying SystemContext (pre-logon control) on a Windows host

How to confirm a perMachine + SystemContext host can be remote-controlled
**pre-logon** (at the Windows logon / lock screen with no user signed in).
The fixes this verifies landed in rc.51/rc.52 — any current release includes
them; the per-step "rc.52" anchors below identify *which* behaviour is being
checked, not a version you should install. The easiest way to set up such a
host today is the `meshharbor-setup` wizard's **Daemon — system** role
([installation.md](installation.md)).

This procedure assumes you have remote-shell access to the controlled
host (a field host). All PowerShell snippets must run from an
**elevated** prompt (Run as administrator).

---

## 0. Background: what the fix does

- **rc.51** — supervisor's `consecutive_failures` counter now climbs on a
  crash-loop; backoff escalates `2 → 4 → 8 → 16 → 32 → 60 s` instead of
  being pinned at 2 s. A throttled `ERROR` alarm fires at ≥8 failures.
  Infinite respawn is retained (a logon / config-fix recovers the host).
- **rc.52** — the SystemContext worker reads its config from a
  **machine-global** location (`%PROGRAMDATA%\meshharbor\meshharbor\config.toml`),
  which is reachable by LocalSystem **before any user logs in**. The
  parent dir gets an inheritable SYSTEM + Administrators DACL so the
  Agent JWT inside is not world-readable.
- **Self-heal** — the first healthy post-logon run of an rc.50-or-earlier
  SystemContext host copies its existing `%APPDATA%` config to
  `%PROGRAMDATA%`, preserving `machine_id`.

---

## 1. Confirm the host is on rc.52+

```powershell
& "C:\Program Files\MeshHarbor\meshharbord.exe" --version
# expect: 0.3.0-rc.52 (or later)
```

If older, force the update (must be from an **elevated** prompt — the
auto-updater needs admin to write `%ProgramFiles%`):

```powershell
& "C:\Program Files\MeshHarbor\meshharbord.exe" self-update
```

(If the host crash-loops too fast for the worker's in-process updater
to fire, install the rc.52 perMachine MSI from the GitHub release
manually.)

---

## 2. Confirm the machine-global config exists

This is the **crux** of the fix.

```powershell
Test-Path "C:\ProgramData\meshharbor\meshharbor\config.toml"
# expect: True
```

If **False**, populate it via one of:

### 2a. Self-heal (automatic, requires one ≥5 min logged-in healthy run)

1. Log in to the host as the normal user.
2. Confirm the agent service is running and connecting:
   ```powershell
   Get-Service MeshHarbor     # Status: Running
   ```
3. **Leave it idle for ≥5 minutes.** The agent's `clean_run_task` fires
   at the threshold; its log line is:
   ```
   config: self-healed perUser config to machine-global path
       (machine_id preserved; next boot is pre-logon-controllable)
   ```
4. Recheck step 2.

### 2b. Direct write via `enroll --machine-global` (no logon required)

If self-heal isn't viable (kiosk that never gets logged into, or you
can't wait), enroll directly to the machine-global path. **Get a fresh
enrollment token from the admin UI first** — this counts as a new
enrollment for that host:

```powershell
& "C:\Program Files\MeshHarbor\meshharbord.exe" enroll `
    --server https://meshharbor.itachi.fans `
    --token <FRESH-ENROLLMENT-TOKEN> `
    --name <HOST-NAME> `
    --machine-global
```

A non-elevated prompt will fail with a clear message; the command
refuses to silently fall back to `%APPDATA%`.

### 2c. Manual copy (preserves machine_id, no new token needed)

If the host already has a perUser config and you don't want a fresh
enrollment, copy it across as SYSTEM (LocalSystem can write `%PROGRAMDATA%`,
your admin token can with elevation):

```powershell
$Src = "C:\Users\<the-enrolling-user>\AppData\Roaming\meshharbor\meshharbor\config\config.toml"
$Dst = "C:\ProgramData\meshharbor\meshharbor\config.toml"
New-Item -ItemType Directory -Force -Path (Split-Path $Dst) | Out-Null
Copy-Item $Src $Dst
```

`machine_id` is a stored field inside `config.toml` so a copy
preserves it; the server's `agents` row stays the same.

---

## 3. Confirm the ACL is locked down

The Agent JWT inside `config.toml` must not be world-readable.

```powershell
icacls "C:\ProgramData\meshharbor"
# expect ONLY entries for:
#   NT-AUTORITÄT\SYSTEM          (F)(OI)(CI)   — well-known SID S-1-5-18
#   VORDEFINIERT\Administratoren (F)(OI)(CI)   — well-known SID S-1-5-32-544
# (German Windows shows localised names; the SIDs are constant.)
# `Users` / `Authenticated Users` should NOT appear.
```

If `Users` appears, the wizard's `harden_machine_global_dir` step never
ran (typical for an auto-update path rather than a fresh wizard
install). Apply it manually — one command:

```powershell
icacls "C:\ProgramData\meshharbor" /inheritance:r `
       /grant:r "*S-1-5-18:(OI)(CI)F" `
       /grant:r "*S-1-5-32-544:(OI)(CI)F"
```

Verify a non-admin user truly cannot read it:

```powershell
# From a NON-elevated PowerShell signed in as a normal user:
Get-Content "C:\ProgramData\meshharbor\meshharbor\config.toml"
# expect: "Access to the path … is denied"
```

---

## 4. The decisive test — pre-logon control

This is what SystemContext exists for.

1. **Reboot the host.**
2. **Do NOT log in.** Leave it at the Windows lock / logon screen.
3. From your browser controller (`https://meshharbor.itachi.fans`), open a remote
   session to the host.
4. **You should see the Winlogon screen** and be able to type the
   password / drive the SAS sequence.

Pre-rc.52 this was impossible — the worker crash-looped because it
couldn't find a config before logon.

---

## 5. Confirm in the agent log

The service-supervisor log lives at
`C:\ProgramData\meshharbor\meshharbor\service-logs\meshharbord-service.log.<date>`
(or fetch via the browser's log viewer panel).

### Healthy rc.52 — these lines should be present:

```
config: resolved load path
    config_path=C:\ProgramData\meshharbor\meshharbor\config.toml
    is_system_context=true
    machine_global=C:\ProgramData\meshharbor\meshharbor\config.toml
supervisor: M3 A1 auto-swap (user-context -> SystemContext) is ENABLED
supervisor: spawned SYSTEM-context worker via winlogon-token
```

Then **steady** `VP9-444 DC pump heartbeat` lines once a controller
connects — no respawn churn.

### The bug is gone if you DO NOT see:

- `config: SystemContext worker but couldn't resolve active-user profile`
  (the rc.48 failure line — must be absent post-rc.52).
- `worker exited with non-zero code … backing off` repeating every
  ~2.5 s. A few during the first minute after a reboot are acceptable
  (rc.51's normal escalating backoff); a sustained stream is not.
- `supervisor: worker has failed N times in a row` (rc.51's alarm).
  If this fires, **rc.52's config fix did not take** — go back to
  step 2.

---

## 6. Quick fail triage

| Symptom in the log | Likely cause | Fix |
|---|---|---|
| `config_path = …\systemprofile\AppData\…` (NOT `%PROGRAMDATA%`) | `%PROGRAMDATA%\meshharbor\meshharbor\config.toml` is missing | redo step 2 (self-heal didn't fire, or no machine-global write yet) |
| `supervisor: worker has failed N times in a row` after a reboot, never recovering | machine-global config missing | step 2 |
| `enroll --machine-global` → "requires elevated terminal" | not running as admin | re-open PowerShell as Administrator |
| Worker starts post-logon but crash-loops pre-logon | self-heal hasn't run yet (needs one ≥5 min healthy logged-in run) OR use step 2b directly | step 2a wait, or step 2b explicit |
| `Users` appears in `icacls` output | rc.52 dir-DACL wasn't applied (typical for auto-update path) | run the manual `icacls` from step 3 |
| `crash_recorder: suppressed sidecar write … reason=HardCapReached` flooding the log | `%PROGRAMDATA%\meshharbor\meshharbor\crashes\` filled up (100 file cap) while crash-looping; uploader can't drain because worker never starts | step 2 first (fixes the loop), then `Remove-Item C:\ProgramData\meshharbor\meshharbor\crashes\*.json` to clear the backlog |

---

## 7. Auto-fail conditions

Any of these means rc.52 hasn't actually fixed this host:

- After completing step 2, the `config: resolved load path` log line
  still names a path other than `C:\ProgramData\…\config.toml`.
- After a reboot **without** logging in, the controller cannot reach
  the Winlogon screen and the supervisor log shows continued
  non-zero exits.
- A non-admin local user can read `config.toml` (token leak — step 3
  ACL is missing).
- `machine_id` differs from the server's stored row for this agent
  (run `meshharbord --config C:\ProgramData\meshharbor\meshharbor\config.toml`
  through any inspect path, OR compare the server-side `agents`
  document `machine_id` field).
