# Run in the same x64 MSVC developer environment as the daemon release build.
param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
& rustc +1.95.0 --edition=2021 --target x86_64-pc-windows-msvc -C opt-level=2 -C target-feature=+crt-static (Join-Path $PSScriptRoot 'task-helper.rs') -o $Output
if($LASTEXITCODE -ne 0){throw 'MSI task helper compilation failed'}
