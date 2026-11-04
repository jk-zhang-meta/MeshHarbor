# vpn-lab.ps1 — autonomous Check Point VPN cycle lab (runs ON the corp laptop).
#
# Drives trac.exe connect/disconnect cycles while sampling overlay health, so the
# whole corp-VPN transition matrix can be measured without a human clicking the
# client. Deployed to C:\ProgramData\meshharbor\vpnlab\ and launched DETACHED via a
# SYSTEM scheduled task (survives control-WS churn on the fleet-exec path that
# started it).
#
# Credentials: read at runtime from C:\dev\OE_VPN.txt (line 1 = username,
# line 2 = password). The file is placed out-of-band (operator, P2P file
# transfer) and its content must never transit fleet exec (exec_audit stores
# commands verbatim) — this script therefore takes NO credential parameters.
#
# Safety rails (non-negotiable):
#   * kill-switch: refuses to run while C:\ProgramData\meshharbor\vpnlab\DISABLED exists
#   * failsafe: before every connect a one-shot SYSTEM task is registered that
#     force-disconnects at now+hold+3min — the machine returns to a reachable
#     state even if every remote path is lost mid-experiment
#   * fail-fast auth: a connect that does not reach Connected is TERMINAL for
#     the run; an auth-suspect error string stops everything (no lockout risk)
#   * cycle count clamped to 6 per run

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('status', 'connect', 'disconnect', 'cycle', 'selftest', 'restore')]
    [string]$Cmd,
    [int]$Count = 1,
    [int]$HoldSec = 180,
    [int]$RestSec = 120,
    [string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss'),
    # Ping targets: the dev box's overlay IPs in BOTH orgs (org-asymmetric
    # failures are exactly what earlier one-org validation missed).
    [string[]]$Targets = @('100.65.4.2', '100.65.0.6')
)

$ErrorActionPreference = 'Stop'
$Trac = 'C:\Program Files (x86)\CheckPoint\Endpoint Connect\trac.exe'
$MeshHarbor = 'C:\Program Files\MeshHarbor\meshharbor.exe'
$CredFile = 'C:\dev\OE_VPN.txt'
$Base = 'C:\ProgramData\meshharbor\vpnlab'
$RunDir = Join-Path $Base "run-$RunId"
$FailsafeTask = 'meshharbor-vpnlab-failsafe'

function Now-Iso { [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }

function Mark([string]$evt) {
    "$(Now-Iso),$evt" | Add-Content -Path (Join-Path $RunDir 'events.csv')
    Write-Host "$(Now-Iso) $evt"
}

function Get-TracState {
    $out = & $Trac info 2>&1 | Out-String
    if ($out -match 'status:\s*(\S+)') { return $Matches[1] }
    return 'unknown'
}

function Read-Creds {
    $c = Get-Content $CredFile
    if ($c.Count -lt 2) { throw "cred file malformed ($($c.Count) lines)" }
    # Lines may carry a label prefix ("un: …" / "pw: …") — strip it. E1's
    # first connect sent the label as part of the username and the gateway
    # answered "falscher Benutzername" (fail-fast caught it; zero retries).
    $strip = { param($l) ($l -replace '^\s*(un|user|username|pw|pass|password)\s*:\s*', '').Trim() }
    @{ User = & $strip $c[0]; Pass = & $strip $c[1] }
}

function Assert-Enabled {
    if (Test-Path (Join-Path $Base 'DISABLED')) {
        throw 'kill-switch marker present (vpnlab\DISABLED) — refusing to run'
    }
}

# Locale-safe (German Windows: schtasks /SD date parsing differs) via the
# ScheduledTasks cmdlets, which take real DateTime objects.
function Arm-Failsafe([int]$holdSec) {
    $at = (Get-Date).AddSeconds($holdSec + 180)
    $action = New-ScheduledTaskAction -Execute $Trac -Argument 'disconnect'
    $trigger = New-ScheduledTaskTrigger -Once -At $at
    Register-ScheduledTask -TaskName $FailsafeTask -Action $action -Trigger $trigger `
        -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
    Mark "FAILSAFE_ARMED,$($at.ToUniversalTime().ToString('HH:mm:ssZ'))"
}

function Disarm-Failsafe {
    Unregister-ScheduledTask -TaskName $FailsafeTask -Confirm:$false -ErrorAction SilentlyContinue
}

function Snapshot-Routes([string]$tag) {
    route print > (Join-Path $RunDir "routes-$tag.txt") 2>&1
}

# One background job per ping target: 1 s cadence, 1000 ms timeout, own CSV
# (no file contention). System.Net Ping — Test-Connection's loss-path latency
# is multi-second on PS 5.1.
function Start-Samplers {
    $jobs = @()
    foreach ($t in $Targets) {
        $jobs += Start-Job -Name "ping-$t" -ScriptBlock {
            param($target, $csv)
            $p = New-Object System.Net.NetworkInformation.Ping
            while ($true) {
                $ts = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                try {
                    $r = $p.Send($target, 1000)
                    "$ts,$($r.Status),$($r.RoundtripTime)" | Add-Content -Path $csv
                } catch {
                    "$ts,SendError,-1" | Add-Content -Path $csv
                }
                Start-Sleep -Milliseconds 1000
            }
        } -ArgumentList $t, (Join-Path $RunDir "ping-$($t.Replace('.','_')).csv")
    }
    # Overlay health: rendered `status` every 10 s (srflx + warm + carrier
    # lines), rendered `peers` every 30 s. Rendered text keeps the sampler
    # schema-independent and the collected run dir small.
    $jobs += Start-Job -Name 'meshharbor-sampler' -ScriptBlock {
        param($meshharbor, $dir)
        $i = 0
        while ($true) {
            $ts = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            try {
                "=== $ts status" | Add-Content -Path (Join-Path $dir 'meshharbor-samples.txt')
                & $meshharbor status 2>&1 | Add-Content -Path (Join-Path $dir 'meshharbor-samples.txt')
                if ($i % 3 -eq 0) {
                    "=== $ts peers" | Add-Content -Path (Join-Path $dir 'meshharbor-samples.txt')
                    & $meshharbor peers 2>&1 | Add-Content -Path (Join-Path $dir 'meshharbor-samples.txt')
                }
            } catch {}
            $i++
            Start-Sleep -Seconds 10
        }
    } -ArgumentList $MeshHarbor, $RunDir
    return $jobs
}

function Connect-Vpn {
    Assert-Enabled
    $cred = Read-Creds
    Mark 'CONNECT_ISSUED'
    # Default site (trac info shows exactly one, active). Output is captured to
    # the run dir for transition forensics — trac never echoes the password.
    $out = & $Trac connect -u $cred.User -p $cred.Pass 2>&1 | Out-String
    $out | Add-Content -Path (Join-Path $RunDir 'trac-connect.log')
    # Match actual FAILURE phrases only (German + English gateways) — benign
    # progress lines like "Authentication done" appear on every success.
    if ($out -match 'Zugriff verweigert|falscher Benutzername|falsches Passwort|Access denied|wrong user|wrong password') {
        Mark 'CONNECT_AUTH_REJECTED_ABORT'
        throw 'gateway rejected the credentials — aborting the whole run (no retry, ever)'
    }
    $deadline = (Get-Date).AddSeconds(90)
    while ((Get-Date) -lt $deadline) {
        if ((Get-TracState) -eq 'Connected') { Mark 'CONNECTED'; return }
        Start-Sleep -Seconds 2
    }
    Mark 'CONNECT_TIMEOUT'
    & $Trac disconnect 2>&1 | Out-Null
    throw 'connect did not reach Connected in 90 s — run aborted'
}

function Disconnect-Vpn {
    Mark 'DISCONNECT_ISSUED'
    & $Trac disconnect 2>&1 | Add-Content -Path (Join-Path $RunDir 'trac-connect.log')
    $deadline = (Get-Date).AddSeconds(45)
    while ((Get-Date) -lt $deadline) {
        if ((Get-TracState) -ne 'Connected') { Mark 'DISCONNECTED'; return }
        Start-Sleep -Seconds 2
    }
    Mark 'DISCONNECT_TIMEOUT'
}

switch ($Cmd) {
    'status' {
        "trac: $(Get-TracState)"
        "killswitch: $(Test-Path (Join-Path $Base 'DISABLED'))"
        Get-ChildItem $Base -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name | Select-Object -Last 3 -ExpandProperty Name
    }
    'selftest' {
        New-Item -ItemType Directory -Path $RunDir -Force | Out-Null
        $ok = $true
        foreach ($check in @(
                @{ n = 'trac.exe present'; f = { Test-Path $Trac } },
                @{ n = 'meshharbor.exe present'; f = { Test-Path $MeshHarbor } },
                @{ n = 'cred file 2 lines'; f = { (Get-Content $CredFile).Count -ge 2 } },
                @{ n = 'trac info parses'; f = { (Get-TracState) -ne 'unknown' } },
                @{ n = 'run dir writable'; f = { Mark 'SELFTEST'; $true } },
                @{ n = 'failsafe arm/disarm'; f = { Arm-Failsafe 60; Disarm-Failsafe; $true } }
            )) {
            try { $r = & $check.f } catch { $r = $false }
            "$(if ($r) { 'PASS' } else { $ok = $false; 'FAIL' }) $($check.n)"
        }
        $jobs = Start-Samplers
        Start-Sleep -Seconds 12
        $jobs | Stop-Job; $jobs | Remove-Job -Force
        foreach ($t in $Targets) {
            $rows = (Get-Content (Join-Path $RunDir "ping-$($t.Replace('.','_')).csv") -ErrorAction SilentlyContinue | Measure-Object).Count
            "$(if ($rows -ge 8) { 'PASS' } else { $ok = $false; 'FAIL' }) ping sampler $t ($rows rows)"
        }
        $sam = (Get-Content (Join-Path $RunDir 'meshharbor-samples.txt') -ErrorAction SilentlyContinue | Measure-Object).Count
        "$(if ($sam -ge 5) { 'PASS' } else { $ok = $false; 'FAIL' }) meshharbor sampler ($sam lines)"
        "SELFTEST $(if ($ok) { 'PASS' } else { 'FAIL' }) run=$RunId"
    }
    'connect' {
        New-Item -ItemType Directory -Path $RunDir -Force | Out-Null
        Arm-Failsafe $HoldSec
        Connect-Vpn
    }
    'disconnect' {
        New-Item -ItemType Directory -Path $RunDir -Force | Out-Null
        Disconnect-Vpn
        Disarm-Failsafe
    }
    'cycle' {
        Assert-Enabled
        $Count = [Math]::Min($Count, 6)
        New-Item -ItemType Directory -Path $RunDir -Force | Out-Null
        Mark "RUN_START,count=$Count,hold=$HoldSec,rest=$RestSec"
        $jobs = Start-Samplers
        try {
            # Normalize: a cycle measures disconn→(rest)→conn→(hold)→disconn,
            # so a box already Connected contributes its disconnect as the
            # first measured transition instead of skewing cycle 1.
            if ((Get-TracState) -eq 'Connected') {
                Mark 'CYCLE_0_NORMALIZE'
                Snapshot-Routes 'pre-normalize'
                Disconnect-Vpn
                Snapshot-Routes 'post-normalize'
                Start-Sleep -Seconds $RestSec
            }
            for ($i = 1; $i -le $Count; $i++) {
                Mark "CYCLE_${i}_START"
                Snapshot-Routes "c$i-preconn"
                Arm-Failsafe $HoldSec
                Connect-Vpn
                Snapshot-Routes "c$i-connected"
                Start-Sleep -Seconds $HoldSec
                Disconnect-Vpn
                Disarm-Failsafe
                Snapshot-Routes "c$i-postdisc"
                if ($i -lt $Count) { Start-Sleep -Seconds $RestSec }
            }
            Mark 'RUN_DONE'
        } catch {
            Mark "RUN_ABORT,$($_.Exception.Message -replace ',', ';')"
        } finally {
            if ((Get-TracState) -eq 'Connected') {
                Disconnect-Vpn
            }
            Disarm-Failsafe
            # E1 lesson: the interesting overlay churn FOLLOWS the last
            # transition — keep the samplers alive for a post window.
            Mark 'POST_WINDOW_START'
            Start-Sleep -Seconds 90
            $jobs | Stop-Job -ErrorAction SilentlyContinue
            $jobs | Remove-Job -Force -ErrorAction SilentlyContinue
            Mark 'RUN_END'
        }
    }
    'restore' {
        # Put the VPN back how the operator had it (Connected) after an
        # experiment — a plain connect with NO failsafe (a delayed forced
        # disconnect on the operator's working session would be sabotage).
        New-Item -ItemType Directory -Path $RunDir -Force | Out-Null
        Connect-Vpn
    }
}
