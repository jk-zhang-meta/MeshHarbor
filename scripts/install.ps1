# roomler install.ps1 -- terminal-driven install of the Roomler node stack on
# Windows, replicating the roomler-setup wizard's steps without a GUI:
# resolve via the roomler.ai proxy -> download -> sha256-verify -> install ->
# enroll -> autostart. Installs roomlerd + the roomler CLI (both inside the
# MSI since P4b) and places the roomler-desktop companion beside them.
#
# NB this file is deliberately ASCII-only: it is served raw over HTTP
# (GET /api/setup/install.ps1) and must parse identically under Windows
# PowerShell 5.1 (which reads BOM-less files as ANSI -- multibyte UTF-8
# punctuation decodes into smart quotes that BREAK the parser) and pwsh 7.
#
# Usage (download-then-run keeps parameters simple):
#
#   irm https://www.itachi.fans/meshharbor/api/setup/install.ps1 -OutFile install.ps1
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 `
#       -Role daemon-system -Token <enrollment-jwt> [-Server https://www.itachi.fans/meshharbor] `
#       [-Name $env:COMPUTERNAME]
#
#   (One-liner equivalent:
#     & ([scriptblock]::Create((irm https://www.itachi.fans/meshharbor/api/setup/install.ps1))) -Role daemon-system -Token <jwt>
#   )
#
# Roles (same vocabulary as the roomler-setup wizard):
#   daemon-user     perUser MSI -- Scheduled-Task autostart, no UAC.
#                   Run from a NORMAL (non-elevated) shell -- see -AllowElevated.
#   daemon-machine  perMachine MSI -- SCM service 'Roomler'. ELEVATED shell required.
#   daemon-system   perMachine MSI + SystemContext (pre-logon / lock screen /
#                   UAC control). ELEVATED shell required. Default.
#
#   The default role needs an ELEVATED shell; pass '-Role daemon-user' from a
#   normal shell for a no-admin per-user install.
#   tunnel-client   the roomler CLI only ("reach others") -- zip + user PATH.
#                   Run from a NORMAL (non-elevated) shell -- see -AllowElevated.
#
# Switches:
#   -DownloadOnly   resolve + download + verify, print what WOULD run,
#                   touch nothing else (safe on any box).
#   -NoEnroll       install without enrolling (no token needed).
#   -SkipDesktop    daemon roles: don't fetch roomler-desktop.exe.
# RETIRED-NAME-ANCHOR-BEGIN
# 'Roomler Agent' IS the MSI ARP DisplayName, so the uninstall lookups below
# must match it exactly or they find nothing and silently do nothing. The
# roomler-tunnel paths and probes are the install layout on hosts that predate
# the rename; the script has to keep finding what is actually there.
#   -Uninstall      remove Roomler from this box: every 'Roomler Agent' MSI
#                   product registered for this user (HKCU) or machine-wide
#                   (HKLM; needs elevation), plus the tunnel-client archive
#                   install and script-copied leftovers. Ignores -Role.
#   -AllowElevated  skip the elevated-shell refusal for the per-user roles.
#                   A per-user install from an elevated shell registers in
#                   the ELEVATING account's profile (HKCU + %LOCALAPPDATA%):
#                   under over-the-shoulder elevation that is the ADMIN's
#                   profile, so the interactive user's Settings > Apps never
#                   shows it and the autostart lands in the wrong account.
#                   Only use this on UAC-disabled boxes where the shell is
#                   unavoidably full-token.
#
# The enrollment token is single-use and is never echoed.

[CmdletBinding()]
param(
    [ValidateSet('daemon-user', 'daemon-machine', 'daemon-system', 'tunnel-client')]
    [string]$Role = 'daemon-system',
    # ⚠️ FR-50 — REWRITTEN at serve time by the server that hands you this
    # script (crates/modules/fleet/src/setup_release.rs), so a script fetched from
    # a self-hosted Roomler enrols against THAT server. Full reasoning in the
    # matching comment in install.sh. ⚠️ The API holds this exact text as a
    # needle and a unit test asserts it appears exactly once, so editing it
    # fails the build rather than silently disabling the substitution.
    [string]$Server = 'https://www.itachi.fans/meshharbor',
    [string]$Token = '',
    [string]$Name = $env:COMPUTERNAME,
    [switch]$DownloadOnly,
    [switch]$NoEnroll,
    [switch]$SkipDesktop,
    [switch]$Uninstall,
    [switch]$AllowElevated
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Say([string]$msg)  { Write-Host "==> $msg" }
function Warn([string]$msg) { Write-Host "WARNING: $msg" -ForegroundColor Yellow }

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Raw .NET SHA256 rather than Get-FileHash: the cmdlet depends on
# module autoloading (Microsoft.PowerShell.Utility), which constrained
# or oddly-configured hosts sometimes lack; the .NET path works on any
# PowerShell 5.1+ unconditionally.
function Get-Sha256Hex([string]$File) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fs = [System.IO.File]::OpenRead($File)
        try { $hash = $sha.ComputeHash($fs) } finally { $fs.Dispose() }
    } finally { $sha.Dispose() }
    ($hash | ForEach-Object { $_.ToString('x2') }) -join ''
}

# Verify a file against a "sha256:<hex>" digest (GitHub asset format).
# Soft-skips when the digest is absent (older releases lack it).
function Assert-Sha256([string]$File, [string]$Digest) {
    if (-not $Digest) {
        Warn ("no sha256 digest published for " + (Split-Path -Leaf $File) + " -- skipping verification")
        return
    }
    $want = ($Digest -replace '^sha256:', '').ToLower()
    $got = Get-Sha256Hex -File $File
    if ($got -ne $want) {
        throw "sha256 mismatch for ${File}: got $got, want $want"
    }
    Say ("sha256 verified: " + (Split-Path -Leaf $File))
}

# The release roomlerd.exe links the MSVC runtime dynamically (its C++
# encoder objects), and pre-rc.266 MSIs ship no app-local CRT: on a fresh
# Windows box without any VC++ 2015-2022 x64 redistributable the first
# daemon run dies with a loader dialog ("vcruntime140_1.dll was not
# found" -- field report 2026-07-28). rc.266+ MSIs carry the CRT beside
# the EXEs, but the installer proxy caches releases for ~1h and older
# MSIs stay in the wild -- so best-effort heal the machine here: quietly
# install the official redist when it is missing and we are elevated,
# otherwise warn with the one-liner fix and continue.
function Ensure-VcRuntime {
    $sys32 = Join-Path $env:SystemRoot 'System32'
    $missing = @()
    foreach ($n in @('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll', 'msvcp140_1.dll')) {
        if (-not (Test-Path (Join-Path $sys32 $n))) { $missing += $n }
    }
    if ($missing.Count -eq 0) { return }
    Say ("VC++ 2015-2022 x64 runtime is missing or incomplete (no " + ($missing -join ', ') + ")")
    if (-not (Test-Elevated)) {
        Warn "cannot install the VC++ runtime without elevation. If the daemon fails to start with a"
        Warn "missing-DLL error, install JUST the runtime from an ELEVATED PowerShell:"
        Warn "  winget install --id Microsoft.VCRedist.2015+.x64 -e"
        Warn "then re-run this installer back in THIS (non-elevated) shell -- do NOT re-run the"
        Warn "installer itself elevated: a per-user install would land in the elevating account's"
        Warn "profile instead of yours."
        return
    }
    $redist = Join-Path $stage 'vc_redist.x64.exe'
    Say "downloading the Microsoft VC++ runtime (aka.ms/vs/17/release/vc_redist.x64.exe)"
    Invoke-WebRequest -UseBasicParsing 'https://aka.ms/vs/17/release/vc_redist.x64.exe' -OutFile $redist
    Say "installing the VC++ runtime (quiet)"
    $p = Start-Process -FilePath $redist -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru
    if ($p.ExitCode -eq 1638) {
        Warn "vc_redist reports a newer runtime is already registered (exit 1638) -- continuing"
    } elseif ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
        throw "vc_redist.x64.exe exited $($p.ExitCode)"
    } else {
        Say "VC++ runtime installed"
    }
}

$stage = Join-Path $env:TEMP ("roomler-install-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$machineRole = $Role -in @('daemon-machine', 'daemon-system')
if ($machineRole -and -not $DownloadOnly -and -not $Uninstall -and -not (Test-Elevated)) {
    Warn "role '$Role' installs the perMachine MSI and needs an ELEVATED shell."
    Warn "Open 'Terminal (Admin)' / an Administrator PowerShell and re-run the same command there,"
    Warn "or stay in this shell and add: -Role daemon-user   (per-user install, no admin needed)."
    throw "role '$Role' requires an elevated PowerShell (or re-run with -Role daemon-user)."
}

# Mirror-image guard: the per-user roles must NOT run elevated. A perUser
# MSI registers its Add/Remove record ONLY in the installing account's HKCU
# (WiX InstallScope='perUser' emits no ALLUSERS), and %LOCALAPPDATA% follows
# the same token -- under over-the-shoulder elevation (admin credentials for
# a standard user's UAC prompt, the norm on corp boxes) BOTH land in the
# ADMIN's profile: the interactive user's Settings > Apps never shows the
# install and the Scheduled Task autostart belongs to the wrong account.
# Field report 2026-07-31 (winhost-a): invisible daemon-user install ->
# blind re-install -> two flavours on one box. -AllowElevated overrides for
# UAC-disabled boxes where every shell is unavoidably full-token.
if (-not $machineRole -and -not $DownloadOnly -and -not $Uninstall -and -not $AllowElevated -and (Test-Elevated)) {
    Warn "role '$Role' is a PER-USER install, but this shell is ELEVATED."
    Warn "If this elevation used a different admin account, the install would register under"
    Warn "THAT account's profile and never appear in your Settings > Apps / Programs & Features."
    Warn "Re-run from a normal (non-elevated) PowerShell. If the VC++ runtime is missing,"
    Warn "install just that part from an elevated shell first:"
    Warn "  winget install --id Microsoft.VCRedist.2015+.x64 -e"
    throw "refusing an elevated '$Role' install (use -AllowElevated only on a UAC-disabled box)."
}

# Pre-rendered hint fragment for enroll commands. S1b: ONLY the
# SystemContext flavour reads the machine-global config -- a plain-SCM
# daemon's worker runs user-context and reads the per-user file, so
# writing machine-global for 'daemon-machine' left the daemon
# UNENROLLED while the desktop app said "Enrolled" (field bug).
$mgFlag = ''
if ($Role -eq 'daemon-system') { $mgFlag = ' --machine-global' }

Say "roomler install.ps1 -- role=$Role server=$Server"

# --- daemon roles: MSI (carries roomlerd + the roomler CLI) -----------------

function Install-Daemon {
    if (-not $DownloadOnly) { Ensure-VcRuntime }
    $flavour = 'permachine'
    if ($Role -eq 'daemon-user') { $flavour = 'peruser' }
    Say "resolving the $flavour MSI via $Server/api/agent/installer/$flavour/health"
    $health = Invoke-RestMethod -UseBasicParsing "$Server/api/agent/installer/$flavour/health?version=latest"
    $msi = Join-Path $stage $health.filename
    Say ("downloading " + $health.filename + " (tag " + $health.tag + ")")
    Invoke-WebRequest -UseBasicParsing ($Server + $health.uri) -OutFile $msi
    Assert-Sha256 -File $msi -Digest $health.digest

    $sysCtx = '0'
    if ($Role -eq 'daemon-system') { $sysCtx = '1' }
    $msiArgs = "/i `"$msi`" /qn /norestart"
    if ($machineRole) { $msiArgs = $msiArgs + " ENABLE_SYSTEM_CONTEXT=$sysCtx" }

    $installDir = Join-Path $env:ProgramFiles 'Roomler'
    if ($Role -eq 'daemon-user') { $installDir = Join-Path $env:LOCALAPPDATA 'Programs\Roomler' }
    $daemon = Join-Path $installDir 'roomlerd.exe'

    if ($DownloadOnly) {
        Say "download-only: would run: msiexec $msiArgs"
        Say "download-only: would enroll via: '$daemon' enroll --server $Server --token <token> --name '$Name'$mgFlag"
        if (-not $SkipDesktop) { Say "download-only: would place roomler-desktop.exe into $installDir" }
        return
    }

    Say "installing the MSI (quiet)"
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) { throw "msiexec exited $($proc.ExitCode)" }
    if ($proc.ExitCode -eq 3010) { Warn "MSI installation succeeded; restart Windows to complete it." }
    if (-not (Test-Path $daemon)) { throw "install finished but $daemon is missing" }
    Say "installed: $installDir (roomlerd.exe + roomler.exe on PATH for new shells)"

    # Surface WHERE this install registered + the uninstall escape hatch. A
    # perUser MSI's Add/Remove record lives ONLY in the installing account's
    # HKCU, so print the product code here -- removal must never depend on
    # the user finding an entry in Settings > Apps.
    $uninstRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    if ($Role -eq 'daemon-user') { $uninstRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall' }
    $arp = Get-ChildItem $uninstRoot -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
        Where-Object { $_.DisplayName -like 'Roomler Agent*' } |
        Select-Object -First 1
    if ($arp) {
        $hive = ($uninstRoot -split ':')[0]
        Say ("registered: '" + $arp.DisplayName + "' " + $arp.DisplayVersion + " in " + $hive + " (account: " + $env:USERNAME + ")")
        Say ("uninstall later with: msiexec /x " + $arp.PSChildName + "  (or re-run this script with -Uninstall)")
    } else {
        Warn "no 'Roomler Agent' record found in $uninstRoot after install -- uninstall via: install.ps1 -Uninstall"
    }

    if (-not $SkipDesktop) { Install-Desktop -InstallDir $installDir }

    if ($NoEnroll -or -not $Token) {
        if (-not $NoEnroll) { Warn "no -Token given -- skipping enrollment" }
        Say "enroll later with: & '$daemon' enroll --server $Server --token <agent-enrollment-jwt> --name '$Name'$mgFlag"
        return
    }

    Say "enrolling this machine as '$Name' against $Server (token is single-use, never echoed)"
    $enrollArgs = @('enroll', '--server', $Server, '--token', $Token, '--name', $Name)
    # S1b: machine-global is the SystemContext flavour's config source only
    # (see the $mgFlag comment above).
    if ($Role -eq 'daemon-system') { $enrollArgs += '--machine-global' }
    # FR-102 -- the install trace: tell the server HOW this install happened
    # (the device row's install.method / install.scope). Through the
    # ENVIRONMENT, never the --install-method flag: this script installs
    # whatever release is current, and a daemon from before that flag existed
    # refuses an argument it does not know. An older daemon ignores the vars.
    # Scope follows the role: daemon-system = system (LocalSystem service),
    # daemon-user = per-user (Scheduled Task), daemon-machine = attended (a
    # service without SystemContext, usable only beside a signed-in session).
    $env:ROOMLER_INSTALL_METHOD = 'script-ps1'
    $env:ROOMLER_INSTALL_SCOPE = 'system'
    if ($Role -eq 'daemon-user') { $env:ROOMLER_INSTALL_SCOPE = 'per-user' }
    if ($Role -eq 'daemon-machine') { $env:ROOMLER_INSTALL_SCOPE = 'attended' }
    try {
        & $daemon @enrollArgs
        $enrollExit = $LASTEXITCODE
    } finally {
        # $env: is process-wide, and an `irm | iex` run shares the caller's
        # process: left set, a later hand-typed enroll in the same window
        # would be recorded as this script's.
        Remove-Item Env:ROOMLER_INSTALL_METHOD, Env:ROOMLER_INSTALL_SCOPE -ErrorAction SilentlyContinue
    }
    if ($enrollExit -ne 0) { throw "enrollment failed (exit $enrollExit)" }

    # Kick the autostart so the daemon picks up the fresh config now
    # rather than at the next logon / service cycle. Best-effort.
    if ($Role -eq 'daemon-user') {
        Say "starting the Scheduled Task 'Roomler'"
        schtasks /Run /TN Roomler | Out-Null
    } else {
        Say "restarting the 'Roomler' service so it picks up the enrollment"
        try { Restart-Service -Name Roomler -Force } catch { Warn "Restart-Service Roomler: $_" }
    }
    # FR-84 D6: the daemon opens the companion ONCE after a fresh install (the
    # Welcome tour) in the signed-in desktop session, and registers it to start
    # at login ('Roomler Desktop' under ...\CurrentVersion\Run). Nothing to do
    # here -- say so, so an unattended run's log explains the window.
    if (-not $SkipDesktop) {
        Say "on a fresh install the Roomler app opens on the signed-in desktop in a few seconds (Welcome tour)"
    }
}

# The desktop companion is a standalone release EXE (not in the MSI).
# Placing it BESIDE roomlerd.exe is the supported layout -- the tray
# resolves the daemon as a sibling of its own EXE.
function Install-Desktop([string]$InstallDir) {
    Say "resolving roomler-desktop from $Server/api/agent/latest-release"
    try {
        $releases = Invoke-RestMethod -UseBasicParsing "$Server/api/agent/latest-release"
        $asset = $null
        foreach ($r in $releases) {
            if ($r.tag_name -notlike 'agent-v*' -or $r.draft) { continue }
            $asset = $r.assets | Where-Object {
                $_.name -like 'roomler-desktop-*-x86_64-pc-windows-msvc*.exe' -and $_.name -notlike '*.sha256'
            } | Select-Object -First 1
            if ($asset) { break }
        }
        if (-not $asset) { Warn "no roomler-desktop asset found in recent agent releases -- skipped"; return }
        $exe = Join-Path $stage 'roomler-desktop.exe'
        Say ("downloading " + $asset.name)
        Invoke-WebRequest -UseBasicParsing $asset.browser_download_url -OutFile $exe
        Assert-Sha256 -File $exe -Digest $asset.digest
        Copy-Item $exe (Join-Path $InstallDir 'roomler-desktop.exe') -Force
        Say "placed roomler-desktop.exe in $InstallDir"
    } catch {
        Warn "roomler-desktop install skipped: $_"
    }
}

# --- tunnel-client role: CLI zip + user PATH --------------------------------

function Install-TunnelClient {
    Say "resolving the CLI zip via $Server/api/tunnel/installer/windows-x86_64/health"
    $health = Invoke-RestMethod -UseBasicParsing "$Server/api/tunnel/installer/windows-x86_64/health?version=latest"
    $zip = Join-Path $stage $health.filename
    Say ("downloading " + $health.filename + " (tag " + $health.tag + ")")
    Invoke-WebRequest -UseBasicParsing ($Server + $health.uri) -OutFile $zip
    Assert-Sha256 -File $zip -Digest $health.digest

    # The roomler-setup wizard's canonical per-user install root -- a
    # script install lands where the wizard (and its detect) expects.
    $installDir = Join-Path $env:LOCALAPPDATA 'roomler\roomler-tunnel\Programs\roomler-tunnel'

    if ($DownloadOnly) {
        Say "download-only: would extract to $installDir, append it to the user PATH,"
        Say "download-only: then enroll via: roomler.exe enroll --server $Server --token <token> --name '$Name'"
        return
    }

    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Expand-Archive -Path $zip -DestinationPath $installDir -Force
    # Archives ship BOTH names since the P3d rename; prefer 'roomler'.
    $cli = $null
    foreach ($n in @('roomler.exe', 'roomler-tunnel.exe')) {
        $found = Get-ChildItem -Path $installDir -Filter $n -Recurse | Select-Object -First 1
        if ($found) { $cli = $found.FullName; break }
    }
    if (-not $cli) { throw "no roomler.exe / roomler-tunnel.exe in the extracted archive" }
    $cliDir = Split-Path -Parent $cli
    Say "installed: $cli"

    $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
    if (-not ($userPath -split ';' | Where-Object { $_ -eq $cliDir })) {
        [Environment]::SetEnvironmentVariable('PATH', ($userPath.TrimEnd(';') + ';' + $cliDir), 'User')
        Say "appended $cliDir to the user PATH (new shells)"
    }
    $env:PATH = "$env:PATH;$cliDir"

    if ($NoEnroll -or -not $Token) {
        if (-not $NoEnroll) { Warn "no -Token given -- skipping enrollment" }
        Say "enroll later with: & '$cli' enroll --server $Server --token <tunnel-enrollment-jwt> --name '$Name'"
        return
    }
    Say "enrolling this tunnel client as '$Name' against $Server (token is single-use, never echoed)"
    & $cli enroll --server $Server --token $Token --name $Name
    if ($LASTEXITCODE -ne 0) { throw "enrollment failed (exit $LASTEXITCODE)" }
}

# --- uninstall: every Roomler install this account can see ------------------

function Uninstall-Roomler {
    # 1) MSI products, both hives. HKCU = perUser flavour (visible only to
    #    the account that installed it -- the reason -Uninstall exists);
    #    HKLM = perMachine flavours (need elevation to remove).
    $roots = @(
        @{ Hive = 'HKCU'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall' },
        @{ Hive = 'HKLM'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
    )
    $found = @()
    foreach ($r in $roots) {
        Get-ChildItem $r.Path -ErrorAction SilentlyContinue |
            ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
            Where-Object { $_.DisplayName -like 'Roomler Agent*' -and $_.PSChildName -like '{*}' } |
            ForEach-Object {
                $found += @{ Hive = $r.Hive; Code = $_.PSChildName; Name = $_.DisplayName; Version = $_.DisplayVersion }
            }
    }
    if ($found.Count -eq 0) {
        Say "no 'Roomler Agent' MSI products registered for this account or machine-wide."
    }
    $uninstallProblems = @()
    foreach ($p in $found) {
        if ($p.Hive -eq 'HKLM' -and -not (Test-Elevated)) {
            Warn ("'" + $p.Name + "' " + $p.Version + " is a perMachine install -- re-run -Uninstall from an")
            Warn ("ELEVATED PowerShell to remove it, or run: msiexec /x " + $p.Code + " /qn")
            $uninstallProblems += "machine-wide MSI needs elevation: $($p.Code)"
            continue
        }
        # Best-effort pre-stop so msiexec's FilesInUse never wedges a /qn
        # uninstall (the rc.236 self-update lesson): the MSI's own custom
        # actions also stop these, this just makes it deterministic.
        if ($p.Hive -eq 'HKCU') { schtasks /End /TN Roomler 2>$null | Out-Null }
        else { try { Stop-Service -Name Roomler -Force -ErrorAction SilentlyContinue } catch {} }
        Say ("uninstalling '" + $p.Name + "' " + $p.Version + " (" + $p.Code + ", " + $p.Hive + ")")
        $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList ("/x " + $p.Code + " /qn /norestart") -Wait -PassThru
        if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
            Warn ("msiexec /x exited " + $proc.ExitCode)
            $uninstallProblems += "MSI $($p.Code) exited $($proc.ExitCode)"
        } elseif ($proc.ExitCode -eq 3010) {
            Warn "MSI removal command succeeded; restart Windows to finish pending file operations."
        } else { Say "MSI removal command completed." }
    }

    # A failed/skipped MSI is still an installation. Preserve its companion,
    # login start and client state; a warning followed by "done" hid a partial
    # uninstall and removed files that the surviving product still needed.
    if ($uninstallProblems.Count -gt 0) {
        throw ("Roomler MSI removal is incomplete: " + ($uninstallProblems -join "; ") + ". Remaining companion, startup and tunnel-client state was preserved.")
    }
    # Observe product absence before removing script-owned leftovers. Registry
    # views can settle briefly after msiexec; read only, never repeat /x.
    $remaining = @()
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        $remaining = @()
        foreach ($r in $roots) {
            try {
                $keys = @(Get-ChildItem -LiteralPath $r.Path -ErrorAction Stop)
            } catch [System.Management.Automation.ItemNotFoundException] { continue }
            catch { throw "Could not enumerate MSI registrations in $($r.Hive); remaining companion, startup and tunnel-client state was preserved." }
            foreach ($key in $keys) {
                try { $product = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop }
                catch [System.Management.Automation.ItemNotFoundException] { continue }
                catch { throw "Could not read an MSI registration in $($r.Hive); remaining companion, startup and tunnel-client state was preserved." }
                if ($product.DisplayName -like 'Roomler Agent*' -and $product.PSChildName -like '{*}') {
                    $remaining += $product.PSChildName
                }
            }
        }
        if ($remaining.Count -eq 0) { break }
        if ($attempt -lt 2) { Start-Sleep -Milliseconds 200 }
    }
    if ($remaining.Count -gt 0) {
        throw "Roomler MSI products are still registered; removal is pending or incomplete. Remaining companion, startup and tunnel-client state was preserved. Resolve the MSI state and re-run -Uninstall."
    }

    # 1b) FR-84 D6: the companion's login start. The MSI's uninstall custom
    #     action removes it (service uninstall); this is the belt for a host
    #     whose MSI record was already gone. HKCU always; HKLM needs elevation.
    $runKeys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')
    if (Test-Elevated) { $runKeys += 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' }
    foreach ($rk in $runKeys) {
        if (Get-ItemProperty -Path $rk -Name 'Roomler Desktop' -ErrorAction SilentlyContinue) {
            try {
                Remove-ItemProperty -Path $rk -Name 'Roomler Desktop' -ErrorAction Stop
                Say "removed the Roomler Desktop login start ($rk)"
            } catch { Warn "could not remove the Roomler Desktop login start in ${rk}: $_" }
        }
    }

    # 2) Script-copied leftovers the MSI never owned: roomler-desktop.exe
    #    (placed by Install-Desktop) + the then-empty install dir.
    foreach ($dir in @((Join-Path $env:ProgramFiles 'Roomler'), (Join-Path $env:LOCALAPPDATA 'Programs\Roomler'))) {
        $desk = Join-Path $dir 'roomler-desktop.exe'
        if (Test-Path $desk) {
            try {
                Get-Process -Name 'roomler-desktop' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Path -like ($dir + '*') } | Stop-Process -Force -ErrorAction SilentlyContinue
                Remove-Item $desk -Force
                Say "removed leftover $desk"
                if (-not (Get-ChildItem $dir -ErrorAction SilentlyContinue)) { Remove-Item $dir -Force }
            } catch { Warn "could not remove ${desk}: $_" }
        }
    }

    # 3) The tunnel-client role (archive install -- by construction it has
    #    NO Add/Remove record anywhere): dir + its user-PATH entry.
    $tcRoot = Join-Path $env:LOCALAPPDATA 'roomler\roomler-tunnel'
    if (Test-Path $tcRoot) {
        try {
            Get-Process -Name 'roomler', 'roomler-tunnel' -ErrorAction SilentlyContinue |
                Where-Object { $_.Path -like ($tcRoot + '*') } | Stop-Process -Force -ErrorAction SilentlyContinue
            $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
            if ($userPath) {
                $kept = ($userPath -split ';' | Where-Object { $_ -and ($_ -notlike ($tcRoot + '*')) }) -join ';'
                if ($kept -ne $userPath) {
                    [Environment]::SetEnvironmentVariable('PATH', $kept, 'User')
                    Say "removed the tunnel-client entry from the user PATH"
                }
            }
            Remove-Item -Recurse -Force $tcRoot
            Say "removed $tcRoot"
        } catch { Warn "tunnel-client cleanup: $_" }
    }
}

# --- main -------------------------------------------------------------------

try {
    if ($Uninstall) { Uninstall-Roomler }
    elseif ($Role -eq 'tunnel-client') { Install-TunnelClient }
    else { Install-Daemon }
    Say "done."
} finally {
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
# RETIRED-NAME-ANCHOR-END
