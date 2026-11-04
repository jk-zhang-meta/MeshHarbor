<#
M5 verification harness for Windows Service deployment mode.

The agent has shipped two autostart strategies on Windows since 0.1.58:
  - Scheduled Task (default, perUser MSI's RegisterAutostart custom action).
    Logs to %LOCALAPPDATA%\roomler\roomler\data\logs\.
  - SCM service `Roomler` (M1 + M2, opt-in via
    `roomlerd service install --as-service` from elevated PS).
    Logs to %PROGRAMDATA%\roomler\roomler\service-logs\.

Until M5, only the Scheduled Task path was field-tested. This script
swaps one for the other, runs the host through a manual logout/login
matrix, captures the supervisor logs at each transition, and is fully
reversible (-Action Rollback). Runs on the field-test host (the dev box) but
should work on any Win11 host where the agent's perUser MSI is
already installed.

Usage:
  pwsh -ExecutionPolicy Bypass -File m5-verify-win11.ps1 -Action Status
  pwsh -ExecutionPolicy Bypass -File m5-verify-win11.ps1 -Action Install   # elevated
  pwsh -ExecutionPolicy Bypass -File m5-verify-win11.ps1 -Action Logs
  pwsh -ExecutionPolicy Bypass -File m5-verify-win11.ps1 -Action Rollback  # elevated

The Install/Rollback actions need an elevated PS session. The script
self-checks and aborts with a clear message if not elevated.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Status', 'Install', 'Rollback', 'Logs', 'SystemLogs', 'Smoke', 'Restart')]
    [string]$Action,

    # Override the agent EXE path. Defaults to the perUser MSI install
    # location. The MSI is installed under the *current* user's
    # %LOCALAPPDATA%, so when running elevated as an admin who is not
    # the install user, supply -AgentExe explicitly.
    [string]$AgentExe = (Join-Path $env:LOCALAPPDATA 'Programs\Roomler\roomlerd.exe'),

    # How many tail lines to print per log file in Logs action.
    [int]$LogTail = 80
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
        Write-Host "       Install the perUser MSI first, or pass -AgentExe <path>."
        exit 3
    }
}

function Get-AgentVersion {
    # `roomlerd --version` prints "roomlerd 0.4.x" or similar.
    try {
        $v = & $AgentExe --version 2>&1
        return ($v | Out-String).Trim()
    } catch {
        return "<unable to query: $($_.Exception.Message)>"
    }
}

function Get-TaskState {
    try {
        $t = Get-ScheduledTask -TaskName 'Roomler' -ErrorAction Stop
        return @{
            Present = $true
            State   = $t.State
            Author  = $t.Principal.UserId
        }
    } catch {
        return @{ Present = $false }
    }
}

function Get-ServiceState {
    $svc = Get-Service -Name 'Roomler' -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        return @{ Present = $false }
    }
    return @{
        Present = $true
        Status  = $svc.Status
        StartType = $svc.StartType
    }
}

function Show-State {
    Write-Host ''
    Write-Host '=== Roomler - Current State ===' -ForegroundColor Cyan
    Write-Host ('Agent EXE: ' + $AgentExe)
    Write-Host ('Agent ver: ' + (Get-AgentVersion))
    $task = Get-TaskState
    if ($task.Present) {
        Write-Host ("Scheduled Task: present, state=$($task.State), runAs=$($task.Author)") -ForegroundColor Green
    } else {
        Write-Host 'Scheduled Task: NOT INSTALLED' -ForegroundColor DarkYellow
    }
    $svc = Get-ServiceState
    if ($svc.Present) {
        $col = if ($svc.Status -eq 'Running') { 'Green' } else { 'DarkYellow' }
        Write-Host ("SCM Service:    present, status=$($svc.Status), startType=$($svc.StartType)") -ForegroundColor $col
    } else {
        Write-Host 'SCM Service:    NOT INSTALLED' -ForegroundColor DarkYellow
    }
    Write-Host ''
}

function Tail-LogDir {
    param(
        [string]$Dir,
        [string]$Label
    )
    Write-Host ''
    Write-Host "=== Logs: $Label ===" -ForegroundColor Cyan
    Write-Host "  dir: $Dir"
    if (-not (Test-Path $Dir)) {
        Write-Host '  (directory does not exist)' -ForegroundColor DarkGray
        return
    }
    # tracing-appender's daily roller writes filenames like
    # `roomlerd.log.2026-05-01` (no trailing `.log` extension),
    # so a literal `*.log` filter misses everything. Match the
    # documented prefix instead.
    $files = Get-ChildItem -Path $Dir -Filter 'roomlerd*.log*' -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending |
             Select-Object -First 2
    if (-not $files) {
        Write-Host '  (no roomlerd*.log* files)' -ForegroundColor DarkGray
        return
    }
    foreach ($f in $files) {
        Write-Host ''
        Write-Host ("  --- $($f.Name)  (last $LogTail lines) ---") -ForegroundColor DarkCyan
        # SYSTEM-profile logs may not be readable from a user-context
        # PS even if the script is elevated; surface the access error
        # instead of silently swallowing it.
        try {
            Get-Content -Path $f.FullName -Tail $LogTail -ErrorAction Stop
        } catch {
            Write-Host "  (read failed: $($_.Exception.Message))" -ForegroundColor Red
        }
    }
}

# ----- actions ---------------------------------------------------------------

function Do-Status {
    Show-State
}

function Do-Logs {
    Show-State
    Tail-LogDir -Dir (Join-Path $env:LOCALAPPDATA 'roomler\roomler\data\logs') -Label 'Scheduled Task / user-mode'
    # The SCM service host runs as LocalSystem, so its logs follow
    # SYSTEM's profile (NOT %PROGRAMDATA%, despite the
    # `default_log_dir()` helper -- `logging::init()` resolves via
    # `directories::ProjectDirs` which targets %LOCALAPPDATA%
    # regardless of who's running. Use -Action SystemLogs (elevated)
    # to read those.
    Write-Host ''
    Write-Host '=== SCM service / SYSTEM logs ===' -ForegroundColor Cyan
    Write-Host '  (run -Action SystemLogs from an elevated PS to read these)' -ForegroundColor DarkGray
}

function Do-Restart {
    # Bounce the SCM service so it reloads the current EXE on disk.
    # Windows services don't follow MSI binary swaps -- the long-
    # lived service-host process keeps running its compiled-in
    # version until an explicit Stop/Start cycle. The user worker
    # gets the new binary because the supervisor spawns it from
    # `current_exe()` after each session change, but the supervisor
    # itself is stale until we restart.
    Require-Elevated
    Show-State
    $svc = Get-ServiceState
    if (-not $svc.Present) {
        Write-Host 'SCM service is not installed; nothing to restart.' -ForegroundColor Red
        exit 5
    }
    Write-Host 'Restarting Roomler (picks up the new EXE on disk)...' -ForegroundColor Cyan
    Restart-Service -Name 'Roomler' -Force
    Start-Sleep -Seconds 2
    Show-State
    Write-Host ''
    Write-Host 'Tip: -Action SystemLogs -LogTail 20  to see the supervisor announce the new version.' -ForegroundColor DarkGray
}

function Do-SystemLogs {
    # Read the SCM service host's log file. The host runs as
    # LocalSystem, so the log lives under SYSTEM's profile:
    # `C:\Windows\System32\config\systemprofile\AppData\Local\roomler\roomler\data\logs\`.
    # Reading that path requires Administrator rights even though the
    # files themselves are owned by SYSTEM (the parent directory
    # ACL is admin-only).
    Require-Elevated
    Show-State
    $sysLocalAppData = Join-Path $env:windir 'System32\config\systemprofile\AppData\Local'
    Tail-LogDir -Dir (Join-Path $sysLocalAppData 'roomler\roomler\data\logs') -Label 'SCM service / SYSTEM (elevated read)'
}

function Do-Smoke {
    Show-State
    # Health probe: the running agent advertises itself to the WS
    # server. We can't easily query the cluster from here without
    # creds, so smoke-test locally - confirm the agent process is
    # alive and the persistent-instance lock is held.
    $procs = Get-Process -Name 'roomlerd' -ErrorAction SilentlyContinue
    if (-not $procs) {
        Write-Host 'No roomlerd.exe processes running.' -ForegroundColor Red
        exit 1
    }
    foreach ($p in $procs) {
        Write-Host ("PID $($p.Id)  start=$($p.StartTime)  RSS=$([math]::Round($p.WorkingSet64/1MB,1)) MB  Path=$($p.Path)")
    }
}

function Do-Install {
    # Switch from Scheduled Task -> SCM service. Idempotent: tolerates
    # already-present SCM service (just ensures it's running) and
    # always drops the Scheduled Task even if the service is already
    # registered. Mixing both autostart hooks creates a sharp edge on
    # logon (Task fires, fights the SCM worker for the instance lock);
    # field repro on the field-test host 2026-05-02 -- both were registered.
    Require-Elevated
    Require-AgentExe

    Show-State
    Write-Host '=== Installing SCM service mode ===' -ForegroundColor Cyan

    $task = Get-TaskState
    $svc  = Get-ServiceState

    # Step 1: ALWAYS drop the Scheduled Task if present, regardless
    # of the SCM service's state. Hosts that ran `service install
    # --as-service` directly (without going through this script)
    # ended up with both registered.
    if ($task.Present) {
        Write-Host 'Removing Scheduled Task (reversible via -Action Rollback)...'
        & $AgentExe service uninstall
        if ($LASTEXITCODE -ne 0) {
            Write-Host "WARNING: 'service uninstall' exited $LASTEXITCODE - task may still be present" -ForegroundColor DarkYellow
        }
    } else {
        Write-Host 'No Scheduled Task to remove.'
    }

    # Step 2: register the SCM service if not already present.
    if (-not $svc.Present) {
        # Stop any orphaned roomlerd worker processes so the
        # supervisor's first spawn doesn't collide with the instance
        # lock held by the old user-mode worker.
        $procs = Get-Process -Name 'roomlerd' -ErrorAction SilentlyContinue
        if ($procs) {
            Write-Host "Stopping $($procs.Count) running roomlerd process(es)..."
            $procs | Stop-Process -Force -ErrorAction Continue
            Start-Sleep -Seconds 2
        }

        Write-Host 'Registering Roomler with SCM...'
        & $AgentExe service install --as-service
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: 'service install --as-service' failed (exit $LASTEXITCODE)" -ForegroundColor Red
            exit 4
        }
    } else {
        Write-Host 'SCM service already registered.'
    }

    # Step 3: ensure it's running.
    $svc = Get-ServiceState
    if ($svc.Status -ne 'Running') {
        Write-Host 'Starting Roomler...'
        Start-Service -Name 'Roomler'
        Start-Sleep -Seconds 2
    }

    Show-State

    Write-Host ''
    Write-Host '=== Next manual steps for M5 verification ===' -ForegroundColor Cyan
    Write-Host '  1. Open the controller (https://roomler.ai/) on a *separate* device,'
    Write-Host '     connect to the field-test host. Confirm video + mouse + keyboard work.'
    Write-Host ''
    Write-Host '  2. While streaming, log out of the field-test host. Expected:'
    Write-Host '     - supervisor logs "console session went idle ... terminating worker"'
    Write-Host '     - browser canvas goes black; agent goes offline in the agent list'
    Write-Host ''
    Write-Host '  3. Log back in. Expected:'
    Write-Host '     - supervisor logs "spawned worker" with new pid'
    Write-Host '     - browser hard-refresh (M3 will fix the F5 dependency) and reconnect: stream resumes'
    Write-Host ''
    Write-Host '  4. Press Win+L to lock; unlock with password. Expected: same logout/login cycle.'
    Write-Host ''
    Write-Host '  5. Run -Action Logs after each transition to capture the supervisor decisions.'
    Write-Host ''
    Write-Host '  Rollback at any point:  pwsh -File m5-verify-win11.ps1 -Action Rollback'
    Write-Host ''
}

function Do-Rollback {
    # Reverse: SCM service -> Scheduled Task.
    Require-Elevated
    Require-AgentExe

    Show-State
    Write-Host '=== Rolling back to Scheduled Task ===' -ForegroundColor Cyan

    $svc = Get-ServiceState
    if ($svc.Present) {
        if ($svc.Status -ne 'Stopped') {
            Write-Host 'Stopping Roomler...'
            try { Stop-Service -Name 'Roomler' -Force -ErrorAction Stop } catch {
                Write-Host "WARNING: stop failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
            }
            Start-Sleep -Seconds 2
        }
        Write-Host 'Unregistering Roomler...'
        & $AgentExe service uninstall --as-service
        if ($LASTEXITCODE -ne 0) {
            Write-Host "WARNING: 'service uninstall --as-service' exited $LASTEXITCODE" -ForegroundColor DarkYellow
        }
    } else {
        Write-Host 'No SCM service to remove.'
    }

    # Stop any orphaned roomlerd processes.
    $procs = Get-Process -Name 'roomlerd' -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Host "Stopping $($procs.Count) running roomlerd process(es)..."
        $procs | Stop-Process -Force -ErrorAction Continue
        Start-Sleep -Seconds 2
    }

    # Re-register the Scheduled Task. `service install` (no --as-service)
    # writes the Schema 1.2 XML and registers it under the *current
    # user* - which means if this script is run elevated as a different
    # admin, the task gets the wrong owner. Run elevated AS the user
    # who owns the agent install.
    $task = Get-TaskState
    if (-not $task.Present) {
        Write-Host 'Re-registering Scheduled Task (ONLOGON, RestartOnFailure)...'
        & $AgentExe service install
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: 'service install' failed (exit $LASTEXITCODE)" -ForegroundColor Red
            exit 4
        }
    }

    Show-State

    Write-Host ''
    Write-Host 'Rollback complete. Log out + back in to trigger the Scheduled Task ONLOGON,' -ForegroundColor Cyan
    Write-Host 'or run the agent manually:  $env:LOCALAPPDATA\Programs\Roomler\roomlerd.exe run'
    Write-Host ''
}

# ----- dispatch --------------------------------------------------------------

switch ($Action) {
    'Status'     { Do-Status }
    'Install'    { Do-Install }
    'Rollback'   { Do-Rollback }
    'Logs'       { Do-Logs }
    'SystemLogs' { Do-SystemLogs }
    'Smoke'      { Do-Smoke }
    'Restart'    { Do-Restart }
}
