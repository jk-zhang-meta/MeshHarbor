# Exact local file transaction; caller owns task stop/start and real health checks.
# Never runs an installer, edits config/tasks, starts a GUI, or contacts a feed.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Apply','Rollback')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$TransactionDir,
    [string]$InstallDir,
    [string]$ManifestPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-PlainPath([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'Absolute paths required' }
    $p = [IO.Path]::GetFullPath($Path)
    while ($p) {
        if (Test-Path -LiteralPath $p) {
            if ((Get-Item -Force -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Reparse point refused: $p"
            }
        }
        $parent = Split-Path -Parent $p
        if ($parent -eq $p) { break }
        $p = $parent
    }
}
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Assert-Stopped([string]$Directory) {
    $prefix = [IO.Path]::GetFullPath($Directory).TrimEnd('\') + '\'
    # Any running executable in the install directory blocks replacement,
    # including desktop/shim/daemon, rather than killing user processes.
    foreach ($p in @(Get-CimInstance Win32_Process)) {
        if ($p.ExecutablePath -and $p.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Install directory still in use by PID $($p.ProcessId)"
        }
        if (-not $p.ExecutablePath -and $p.Name -in @('meshharbord.exe','meshharbor-desktop.exe','mh.exe')) {
            throw 'Cannot establish ownership of a running MeshHarbor process'
        }
    }
}
function Replace-Exact([string]$Source,[string]$Target,[string]$ExpectedSource,[string]$ExpectedTarget) {
    Assert-PlainPath $Source; Assert-PlainPath $Target
    if ((Hash $Source) -ne $ExpectedSource -or (Hash $Target) -ne $ExpectedTarget) { throw 'File changed before replacement' }
    $tmp = $Target + '.mh-stage-' + [Guid]::NewGuid().ToString('N')
    try {
        [IO.File]::Copy($Source,$tmp,$false)
        if ((Hash $tmp) -ne $ExpectedSource -or (Hash $Target) -ne $ExpectedTarget) { throw 'File changed while staging' }
        # Native replacement retains the destination ACL; no MSI/task side effects.
        [IO.File]::Replace($tmp,$Target,[System.Management.Automation.Language.NullString]::Value)
        if ((Hash $Target) -ne $ExpectedSource) { throw 'Replacement hash mismatch' }
    } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force } }
}
function Restore-Files($State) {
    Assert-Stopped $State.install_dir
    # Whole-set preflight before any rollback write. Never overwrite third-state edits.
    foreach ($f in $State.files) {
        $target = Join-Path $State.install_dir $f.name
        $backup = Join-Path $TransactionDir ('baseline\' + $f.name)
        Assert-PlainPath $target; Assert-PlainPath $backup
        if ((Hash $backup) -ne $f.old_sha256) { throw 'Baseline corrupted' }
        if ((Hash $target) -notin @($f.old_sha256,$f.new_sha256)) { throw "Rollback drift: $($f.name)" }
        if ((Get-Acl -LiteralPath $target).Sddl -ne $f.sddl) { throw "Rollback ACL drift: $($f.name)" }
    }
    foreach ($f in $State.files) {
        $target = Join-Path $State.install_dir $f.name
        if ((Hash $target) -eq $f.new_sha256) {
            Replace-Exact (Join-Path $TransactionDir ('baseline\' + $f.name)) $target $f.old_sha256 $f.new_sha256
        }
        $targetItem = Get-Item -LiteralPath $target
        $targetItem.CreationTimeUtc = [DateTime]::Parse($f.creation_utc).ToUniversalTime()
        $targetItem.LastWriteTimeUtc = [DateTime]::Parse($f.modified_utc).ToUniversalTime()
        if ((Get-Acl -LiteralPath $target).Sddl -ne $f.sddl) { throw "ACL drift: $($f.name)" }
    }
    'ROLLBACK_FILES_VERIFIED (task restart and real health checks remain required)'
}

Assert-PlainPath $TransactionDir
if ($Mode -eq 'Rollback') {
    $state = Get-Content -Raw -LiteralPath (Join-Path $TransactionDir 'state.json') | ConvertFrom-Json
    Assert-PlainPath $state.install_dir
    Restore-Files $state
    exit 0
}
Assert-PlainPath $InstallDir; Assert-PlainPath $ManifestPath
if (Test-Path -LiteralPath $TransactionDir) { throw 'Fresh transaction directory required' }
$decoded = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
$files = @($decoded)
if (-not $files.Count) { throw 'Empty manifest' }
$seen = @{}
foreach ($f in $files) {
    if ($f.name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$' -or $seen.ContainsKey($f.name)) { throw 'Unsafe or duplicate filename' }
    $seen[$f.name] = $true
    if ($f.old_sha256 -notmatch '^[a-f0-9]{64}$' -or $f.new_sha256 -notmatch '^[a-f0-9]{64}$') { throw 'Lowercase SHA256 required' }
    Assert-PlainPath $f.source
    $target = Join-Path $InstallDir $f.name
    Assert-PlainPath $target
    if ((Hash $target) -ne $f.old_sha256 -or (Hash $f.source) -ne $f.new_sha256) { throw "Preflight mismatch: $($f.name)" }
}
Assert-Stopped $InstallDir
New-Item -ItemType Directory -Path $TransactionDir | Out-Null
# Backups contain binaries, not config credentials. Still restrict transaction writes.
$acl = Get-Acl -LiteralPath $TransactionDir
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $TransactionDir -AclObject $acl
New-Item -ItemType Directory -Path (Join-Path $TransactionDir 'baseline') | Out-Null
$records = @()
foreach ($f in $files) {
    $target = Join-Path $InstallDir $f.name
    $item = Get-Item -LiteralPath $target
    $backup = Join-Path $TransactionDir ('baseline\' + $f.name)
    [IO.File]::Copy($target,$backup,$false)
    if ((Hash $backup) -ne $f.old_sha256 -or (Hash $target) -ne $f.old_sha256) { throw 'Baseline changed during snapshot' }
    $records += [pscustomobject]@{name=$f.name; source=$f.source; old_sha256=$f.old_sha256; new_sha256=$f.new_sha256; creation_utc=$item.CreationTimeUtc.ToString('o'); modified_utc=$item.LastWriteTimeUtc.ToString('o'); sddl=(Get-Acl -LiteralPath $target).Sddl}
}
$state = [pscustomobject]@{install_dir=[IO.Path]::GetFullPath($InstallDir); files=$records}
$state | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $TransactionDir 'state.json')
Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $TransactionDir 'transaction.ps1')
'$ErrorActionPreference = ''Stop''; & (Join-Path $PSScriptRoot ''transaction.ps1'') -Mode Rollback -TransactionDir $PSScriptRoot; exit $LASTEXITCODE' | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $TransactionDir 'ROLLBACK.ps1')
try {
    foreach ($f in $records) {
        Assert-Stopped $InstallDir
        Replace-Exact $f.source (Join-Path $InstallDir $f.name) $f.new_sha256 $f.old_sha256
        Write-Output ("REPLACED_FILE " + $f.name)
    }
    foreach ($f in $records) {
        $target = Join-Path $InstallDir $f.name
        if ((Hash $target) -ne $f.new_sha256 -or (Get-Acl -LiteralPath $target).Sddl -ne $f.sddl) { throw 'Final hash/ACL mismatch' }
    }
} catch {
    $failure = $_
    Restore-Files $state
    throw $failure
}
'MODIFIED_FILES_VERIFIED (task restart and real health checks remain required)'
