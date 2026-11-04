# Native Windows fixture guard. Run Snapshot BEFORE enrollment/startup and
# Compare AFTER stopping the candidate. Backups belong in private task runtime.
param(
    [Parameter(Mandatory=$true)][ValidateSet('Snapshot','Compare')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$SnapshotRoot
)
$ErrorActionPreference = 'Stop'
if (-not [IO.Path]::IsPathRooted($SnapshotRoot)) { throw 'SnapshotRoot must be absolute' }
$local = [Environment]::GetFolderPath('LocalApplicationData')
if (-not $local) { throw 'KnownFolder LocalApplicationData unavailable' }
$paths = @('meshharbor','meshharbor-agent') | ForEach-Object {
    Join-Path $local "meshharbor\$_\data\keep-busy.json"
}
function Read-StoreState([string]$Path) {
    $state = [ordered]@{ path=$Path; exists=(Test-Path -LiteralPath $Path -PathType Leaf) }
    if ($state.exists) {
        $item = Get-Item -LiteralPath $Path
        $state.hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        $state.length = $item.Length
        $state.creation_utc = $item.CreationTimeUtc.ToString('o')
        $state.modified_utc = $item.LastWriteTimeUtc.ToString('o')
        $state.acl = (Get-Acl -LiteralPath $Path).Sddl
    }
    return [pscustomobject]$state
}
if ($Mode -eq 'Snapshot') {
    if (Test-Path -LiteralPath $SnapshotRoot) { throw 'SnapshotRoot already exists' }
    New-Item -ItemType Directory -Path $SnapshotRoot | Out-Null
    $before = @($paths | ForEach-Object { Read-StoreState $_ })
    for ($i=0; $i -lt $before.Count; $i++) {
        if ($before[$i].exists) {
            Copy-Item -LiteralPath $before[$i].path -Destination (Join-Path $SnapshotRoot "$i.bin")
            if ((Get-FileHash -LiteralPath (Join-Path $SnapshotRoot "$i.bin")).Hash -ne $before[$i].hash) {
                throw 'Store changed while taking snapshot; do not start candidate'
            }
        }
    }
    $before | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $SnapshotRoot 'before.json')
    @{ snapshot_created=$true; stores=$before.Count } | ConvertTo-Json -Compress
} else {
    $before = Get-Content -LiteralPath (Join-Path $SnapshotRoot 'before.json') -Raw | ConvertFrom-Json
    if (@($before).Count -ne $paths.Count) { throw 'Snapshot store count changed' }
    $changed = @()
    for ($i=0; $i -lt $paths.Count; $i++) {
        if ($before[$i].path -ne $paths[$i]) { throw 'Snapshot belongs to another Windows profile' }
        $after = Read-StoreState $paths[$i]
        if (($before[$i] | ConvertTo-Json -Compress) -ne ($after | ConvertTo-Json -Compress)) {
            $changed += $paths[$i]
        }
    }
    $result = @{ unchanged=($changed.Count -eq 0); stores=$paths.Count; changed=$changed }
    $result | ConvertTo-Json -Compress | Tee-Object -FilePath (Join-Path $SnapshotRoot 'comparison.json')
    if ($changed.Count) { throw 'Shared per-person store changed; retain backups, do not guess a restore' }
}
