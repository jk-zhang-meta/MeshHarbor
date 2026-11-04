<#
M3 A1 verification harness — perMachine MSI + SYSTEM-context worker.

Companion to m5-verify-win11.ps1 (which validated the M2 user-context
SCM service path). This one validates the M3 A1 lock-screen-unlock
path that ships with the perMachine MSI build of 0.3.0+:

  - SCM service `Roomler` runs as LocalSystem,
    Session 0.
  - When a controller is mid-session AND the active console session
    is on the lock screen, the supervisor's
    `SpawnDecision::SpawnSystemInSession(sid)` arm fires and uses
    `system_context::winlogon_token` to spawn a worker as S-1-5-18
    in the target interactive session.
  - That worker probes its own SID via `worker_role::probe_self`,
    sees S-1-5-18 → constructs SystemContext-mode
    capture (DXGI Desktop Duplication → GDI fallback) and input
    (dedicated thread with `desktop_rebind::try_change_desktop`
    before each event).
  - Browser sees real lock-screen pixels (not the Z-path overlay)
    + the new "On Winlogon" desktop chip; controller types the host
    password, host unlocks.

This script doesn't drive the controller — that's manual. It:
  1. Verifies the install.
  2. Confirms the SCM service is up and the supervisor is running.
  3. Captures a worker spawn under SYSTEM identity.
  4. Walks the operator through a lock/unlock cycle while
     timestamping the supervisor logs.
  5. Computes lock→unlock visual latency from those timestamps.

Usage:
  pwsh -ExecutionPolicy Bypass -File m3-a1-verify-win11.ps1 -Action Status
  pwsh -ExecutionPolicy Bypass -File m3-a1-verify-win11.ps1 -Action Install   # elevated
  pwsh -ExecutionPolicy Bypass -File m3-a1-verify-win11.ps1 -Action SystemSpawn
  pwsh -ExecutionPolicy Bypass -File m3-a1-verify-win11.ps1 -Action LockUnlockCycle
  pwsh -ExecutionPolicy Bypass -File m3-a1-verify-win11.ps1 -Action Latency
  pwsh -ExecutionPolicy Bypass -File m3-a1-verify-win11.ps1 -Action Logs
  pwsh -ExecutionPolicy Bypass -File m3-a1-verify-win11.ps1 -Action Rollback   # elevated

Acceptance gates (per plan ~/.claude/plans/floating-splashing-nebula.md):
  - SystemSpawn: at least one worker exists with `whoami /user`
    showing `S-1-5-18` AND `session id` != 0.
  - LockUnlockCycle: browser viewer shows real lock-screen pixels
    (operator-confirmed visual check); supervisor log shows
    SpawnSystemInSession(N) for the active session.
  - Latency: from operator's `Win+L` keystroke timestamp to the
    first frame of the lock screen rendered in the browser:
    p50 < 1.5 s, p99 < 3.0 s.

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Status', 'Install', 'SystemSpawn', 'LockUnlockCycle', 'Latency', 'Logs', 'Rollback')]
    [string]$Action,

    # RETIRED-NAME-ANCHOR(2): the PUBLISHED MSI asset name. Release asset
    # names are frozen (FR-21 D6) — the updater matches on extension +
    # arch + the -permachine- infix, never the prefix.
    # Path to the perMachine roomler-agent MSI. Default: the per-tag
    # release asset name pattern from .github/workflows/release-agent.yml.
    [string]$MsiPath = 'C:\Users\Public\Downloads\roomler-agent-perMachine.msi',

    # Override the agent EXE path. Defaults to the perMachine install
    # location.
    [string]$AgentExe = 'C:\Program Files\Roomler\roomlerd.exe',

    # How many tail lines to print per log file in Logs.
    [int]$LogTail = 120,

    # Number of lock/unlock cycles to repeat in LockUnlockCycle.
    [int]$Cycles = 5
)

$ErrorActionPreference = 'Stop'

# ----- helpers ---------------------------------------------------------------

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Require-Elevated {
    if (-not (Test-Elevated)) {
        Write-Host "ERROR: -Action $Action requires an elevated PowerShell session." -ForegroundColor Red
        Write-Host "       Right-click PowerShell -> Run as administrator, then re-run."
        exit 2
    }
}

function Require-AgentExe {
    if (-not (Test-Path $AgentExe)) {
        Write-Host "ERROR: agent EXE not found at: $AgentExe" -ForegroundColor Red
        Write-Host "       Install the perMachine MSI (-Action Install) or pass -AgentExe <path>."
        exit 3
    }
}

function Get-AgentVersion {
    try {
        $v = & $AgentExe --version 2>&1
        return ($v | Out-String).Trim()
    } catch {
        return "<unable to query: $($_.Exception.Message)>"
    }
}

function Get-ServiceState {
    $svc = Get-Service -Name 'Roomler' -ErrorAction SilentlyContinue
    if (-not $svc) { return $null }
    return [pscustomobject]@{
        Status    = $svc.Status
        StartType = $svc.StartType
    }
}

# Under perMachine MSI, BOTH the SCM-service supervisor AND the
# SystemContext worker run as LocalSystem and write to the SYSTEM
# profile's local-app-data path. The user-context worker (when it
# exists) writes to whichever user owns the session. The
# tracing-appender uses daily rolling files named
# `roomlerd.log.YYYY-MM-DD` (NOT `*.log`). Search both
# directories and pick the most recent file across them so the
# operator always gets the freshest log.
function Get-SystemWorkerLogDir {
    return 'C:\Windows\System32\config\systemprofile\AppData\Local\roomler\roomler\data\logs'
}

function Get-UserWorkerLogDirs {
    # Enumerate every C:\Users\*\AppData\Local\... candidate and
    # return only those that exist. Catches sessions where the agent
    # ran as the logged-in user before the perMachine SCM service
    # took over.
    $users = Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue
    $dirs = @()
    foreach ($u in $users) {
        $cand = Join-Path $u.FullName 'AppData\Local\roomler\roomler\data\logs'
        if (Test-Path $cand) { $dirs += $cand }
    }
    return $dirs
}

# Supervisor + SystemContext-worker logs land in the same dir under
# perMachine (both are LocalSystem). Treat them as one search target.
function Get-SupervisorLogDir {
    return Get-SystemWorkerLogDir
}

function Get-LatestLog {
    param([string]$Dir)
    if (-not (Test-Path $Dir)) { return $null }
    # tracing-appender's daily roller uses `roomlerd.log.<date>`
    # so we match both the rolled name AND any `.log` files (in case
    # a future config writes to the unsuffixed name).
    return Get-ChildItem -Path $Dir -Filter 'roomlerd*.log*' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

# Find the freshest agent log across SYSTEM-profile + every user
# profile. Used by Action-Latency to make sure we read the log the
# active worker is currently writing to, regardless of which session
# it's running in.
function Get-LatestLogAcrossDirs {
    $dirs = @(Get-SystemWorkerLogDir)
    $dirs += Get-UserWorkerLogDirs
    $latest = $null
    foreach ($d in $dirs) {
        $cand = Get-LatestLog -Dir $d
        if ($cand) {
            if (-not $latest -or $cand.LastWriteTime -gt $latest.LastWriteTime) {
                $latest = $cand
            }
        }
    }
    return $latest
}

# ----- actions ---------------------------------------------------------------

function Action-Status {
    Write-Host '== M3 A1 status ===========================================' -ForegroundColor Cyan
    Write-Host "Agent EXE: $AgentExe"
    if (Test-Path $AgentExe) {
        Write-Host "Version:   $(Get-AgentVersion)"
    } else {
        Write-Host 'Version:   <not installed>' -ForegroundColor Yellow
    }
    $svc = Get-ServiceState
    if ($svc) {
        Write-Host "Service:   $($svc.Status) ($($svc.StartType))"
    } else {
        Write-Host 'Service:   <not registered>' -ForegroundColor Yellow
    }

    $supLog = Get-LatestLogAcrossDirs
    if ($supLog) {
        Write-Host "Latest log: $($supLog.FullName) ($([math]::Round($supLog.Length/1KB)) KB, $($supLog.LastWriteTime))"
    } else {
        Write-Host 'Latest log: <none>' -ForegroundColor Yellow
    }
    $sysLog = Get-LatestLog (Get-SystemWorkerLogDir)
    if ($sysLog) {
        Write-Host "Sys log:    $($sysLog.FullName) ($([math]::Round($sysLog.Length/1KB)) KB, $($sysLog.LastWriteTime))"
    } else {
        Write-Host 'Sys log:    <none — no SYSTEM-context spawn observed yet>'
    }
    foreach ($d in (Get-UserWorkerLogDirs)) {
        $userLog = Get-LatestLog -Dir $d
        if ($userLog) {
            Write-Host "User log:   $($userLog.FullName) ($([math]::Round($userLog.Length/1KB)) KB, $($userLog.LastWriteTime))"
        }
    }

    # SoftwareSASGeneration check (Critique #12). The perMachine MSI
    # writes 1; without it Ctrl+Alt+Del from the browser controller
    # silently fails on the lock screen.
    $sasKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    $sasVal = (Get-ItemProperty -Path $sasKey -Name 'SoftwareSASGeneration' -ErrorAction SilentlyContinue).SoftwareSASGeneration
    if ($sasVal -eq 1 -or $sasVal -eq 3) {
        Write-Host "SAS gate:  enabled (SoftwareSASGeneration=$sasVal)"
    } else {
        Write-Host "SAS gate:  DISABLED (SoftwareSASGeneration=$sasVal) — Ctrl+Alt+Del from browser will silently fail" -ForegroundColor Yellow
    }
}

function Action-Install {
    Require-Elevated
    if (-not (Test-Path $MsiPath)) {
        Write-Host "ERROR: MSI not found at: $MsiPath" -ForegroundColor Red
        Write-Host "       Pass -MsiPath <path> pointing to the 0.3.0-rcN perMachine MSI."
        exit 4
    }
    Write-Host "Installing $MsiPath ..." -ForegroundColor Cyan
    $proc = Start-Process -FilePath 'msiexec.exe' `
        -ArgumentList '/i', "`"$MsiPath`"", '/qb', '/L*v', "$env:TEMP\m3-a1-install.log" `
        -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Host "msiexec exited $($proc.ExitCode); see $env:TEMP\m3-a1-install.log" -ForegroundColor Red
        exit 5
    }
    Write-Host 'MSI installed. Verifying service registration ...'
    Start-Sleep -Seconds 2
    Action-Status
}

function Action-SystemSpawn {
    Require-AgentExe
    Write-Host '== Looking for SYSTEM-context worker ======================' -ForegroundColor Cyan

    # Find roomlerd.exe processes whose owner is NT AUTHORITY\SYSTEM
    # AND whose session id is non-zero. The supervisor itself (also
    # roomlerd.exe) runs as SYSTEM in session 0; we want the
    # spawned WORKER which lives in an interactive session.
    $procs = Get-CimInstance Win32_Process -Filter "Name='roomlerd.exe'"
    if (-not $procs) {
        Write-Host 'No roomlerd.exe processes found. SCM service running?' -ForegroundColor Yellow
        return
    }
    $hits = @()
    foreach ($p in $procs) {
        $owner = ($p | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue)
        $ownerStr = if ($owner -and $owner.User) { "$($owner.Domain)\$($owner.User)" } else { '<unknown>' }
        $row = [pscustomobject]@{
            PID      = $p.ProcessId
            Session  = $p.SessionId
            Owner    = $ownerStr
            Cmdline  = $p.CommandLine
        }
        $hits += $row
        Write-Host ("  pid={0,5}  session={1}  owner={2}  cmd={3}" -f $p.ProcessId, $p.SessionId, $ownerStr, $p.CommandLine)
    }
    $sysWorker = $hits | Where-Object { $_.Session -ne 0 -and $_.Owner -like '*\SYSTEM' }
    if ($sysWorker) {
        Write-Host ("`nPASS — {0} SYSTEM-context worker(s) running in non-zero session(s)" -f @($sysWorker).Count) -ForegroundColor Green
    } else {
        Write-Host "`nFAIL — no SYSTEM-context worker observed. Is a controller currently connected to the agent?" -ForegroundColor Yellow
        Write-Host "       The supervisor only spawns the SystemContext worker when keep_stream_alive=true."
    }
}

function Action-LockUnlockCycle {
    Require-AgentExe
    Write-Host '== Lock/Unlock cycle harness ==============================' -ForegroundColor Cyan
    Write-Host "About to run $Cycles lock/unlock cycles. For each cycle:"
    Write-Host '  1. Connect from a browser controller (roomler.ai)'
    Write-Host '  2. Press Win+L on the host'
    Write-Host '  3. Observe the browser viewer — should show real lock-screen pixels (not Z-path overlay)'
    Write-Host '  4. Type the host password from the browser controller'
    Write-Host '  5. Observe the host unlocks'
    Write-Host ''
    Read-Host 'Press Enter to begin cycle 1 (or Ctrl+C to abort)'

    $marker = Get-Date
    Write-Host "Marker timestamp: $marker"
    Write-Host '(All supervisor / worker log lines emitted from now on are part of this run.)'

    for ($i = 1; $i -le $Cycles; $i++) {
        Write-Host ("`n-- Cycle {0}/{1} --" -f $i, $Cycles) -ForegroundColor Cyan
        Read-Host 'Press Enter when you have completed Win+L → unlock ONCE'
    }
    Write-Host "`nAll cycles complete. Run -Action Latency next to extract metrics."
    Write-Host "Marker: $marker"
}

function Action-Latency {
    Write-Host '== Lock-Unlock latency analysis ===========================' -ForegroundColor Cyan
    $supLog = Get-LatestLogAcrossDirs
    if (-not $supLog) {
        Write-Host 'No supervisor log found in any candidate directory.' -ForegroundColor Yellow
        Write-Host '  Tried:' -ForegroundColor DarkGray
        Write-Host "    $(Get-SystemWorkerLogDir)" -ForegroundColor DarkGray
        foreach ($d in (Get-UserWorkerLogDirs)) {
            Write-Host "    $d" -ForegroundColor DarkGray
        }
        return
    }
    Write-Host "Reading: $($supLog.FullName)"

    # Look for SpawnSystemInSession + worker-spawn timestamps. The
    # actual visual latency (Win+L keystroke → browser frame paints)
    # cannot be measured from the agent side alone — the browser's
    # rVFC timestamp is needed for that. This action gives the
    # operator the agent-side half of the budget; the browser side
    # is captured in the developer console with `performance.now()`
    # bracketing the WS rc:host_locked event.
    $log = Get-Content -Path $supLog.FullName -Tail 5000 -ErrorAction SilentlyContinue
    $events = @()
    foreach ($line in $log) {
        if ($line -match 'SpawnSystemInSession|spawned SYSTEM-context worker|host_locked|desktop_changed|rc:resolution') {
            $events += $line
        }
    }
    if ($events.Count -eq 0) {
        Write-Host 'No M3 A1 transition events in the recent supervisor log.' -ForegroundColor Yellow
        return
    }
    Write-Host "Found $($events.Count) M3 A1 transition events:`n"
    $events | Select-Object -Last 60 | ForEach-Object { Write-Host "  $_" }
    Write-Host "`nFor full visual latency: open browser DevTools, capture rc:host_locked → first rVFC frame timestamps."
    Write-Host 'Acceptance: p50 < 1.5 s, p99 < 3.0 s from key-press to first lock-screen frame.'
}

function Action-Logs {
    Write-Host '== Latest agent log (any source) ==========================' -ForegroundColor Cyan
    $latest = Get-LatestLogAcrossDirs
    if ($latest) {
        Write-Host $latest.FullName
        Get-Content -Path $latest.FullName -Tail $LogTail
    } else {
        Write-Host 'No agent log found.' -ForegroundColor Yellow
    }
    Write-Host "`n== System-context worker log =============================" -ForegroundColor Cyan
    $sysLog = Get-LatestLog (Get-SystemWorkerLogDir)
    if ($sysLog) {
        Write-Host $sysLog.FullName
        Get-Content -Path $sysLog.FullName -Tail $LogTail
    } else {
        Write-Host 'No SYSTEM-context worker log (worker may not have spawned yet).' -ForegroundColor Yellow
    }
    Write-Host "`n== User-context worker logs ==============================" -ForegroundColor Cyan
    foreach ($d in (Get-UserWorkerLogDirs)) {
        $userLog = Get-LatestLog -Dir $d
        if ($userLog) {
            Write-Host $userLog.FullName
            Get-Content -Path $userLog.FullName -Tail ([math]::Min($LogTail, 50))
            Write-Host '---'
        }
    }
}

function Action-Rollback {
    Require-Elevated
    Write-Host '== Rolling back perMachine 0.3.0-rc =======================' -ForegroundColor Cyan
    # Locate the installed product code via msiexec query — perMachine
    # MSI's UpgradeCode is the one in wix-perMachine/main.wxs.
    $upgradeCode = '{2A8E9C2D-3F1A-5E3F-C2B4-7C2F3D8F5E02}'
    # RETIRED-NAME-ANCHOR: "Roomler Agent (per-Machine)" IS the ARP
    # DisplayName (wix-perMachine/main.wxs). Changing it here finds
    # nothing; changing it THERE orphans every installed agent.
    $product = Get-CimInstance Win32_Product -Filter "Name LIKE '%Roomler Agent (per-Machine)%'" -ErrorAction SilentlyContinue
    if (-not $product) {
        Write-Host 'No perMachine Roomler install found. Nothing to roll back.' -ForegroundColor Yellow
        return
    }
    Write-Host "Uninstalling $($product.Name) ($($product.Version)) ..."
    $proc = Start-Process -FilePath 'msiexec.exe' `
        -ArgumentList '/x', $product.IdentifyingNumber, '/qb', '/L*v', "$env:TEMP\m3-a1-uninstall.log" `
        -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Host "msiexec /x exited $($proc.ExitCode); see $env:TEMP\m3-a1-uninstall.log" -ForegroundColor Red
        exit 6
    }
    Write-Host 'Rollback complete. SCM service should be unregistered; SoftwareSASGeneration value removed.'
    Write-Host 'Verify with -Action Status.'
}

# ----- dispatch --------------------------------------------------------------

switch ($Action) {
    'Status'           { Action-Status }
    'Install'          { Action-Install }
    'SystemSpawn'      { Action-SystemSpawn }
    'LockUnlockCycle'  { Action-LockUnlockCycle }
    'Latency'          { Action-Latency }
    'Logs'             { Action-Logs }
    'Rollback'         { Action-Rollback }
}
