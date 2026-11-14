param(
  [Parameter(Mandatory=$true)][string]$Script,
  [Parameter(Mandatory=$true)][string]$FixtureRoot
)
$ErrorActionPreference='Stop'
$w=Join-Path $FixtureRoot ('mh-file-transaction-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $w | Out-Null
$install=New-Item -ItemType Directory -Path (Join-Path $w 'install')
$source=New-Item -ItemType Directory -Path (Join-Path $w 'source')
$manifest=@()
foreach($name in @('daemon.bin','desktop.bin')) {
  $old=Join-Path $install.FullName $name; $new=Join-Path $source.FullName $name
  [IO.File]::WriteAllText($old,'BASELINE-'+$name)
  [IO.File]::WriteAllText($new,'MODIFIED-'+$name)
  $manifest+=@{name=$name;source=$new;old_sha256=(Get-FileHash $old).Hash.ToLower();new_sha256=(Get-FileHash $new).Hash.ToLower()}
}
$mp=Join-Path $w 'manifest.json'; $manifest | ConvertTo-Json | Set-Content -Encoding UTF8 $mp
$tx=Join-Path $w 'transaction'
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Script -Mode Apply -InstallDir $install.FullName -TransactionDir $tx -ManifestPath $mp
if($LASTEXITCODE -ne 0){throw 'Apply failed'}
foreach($f in $manifest){if((Get-FileHash (Join-Path $install.FullName $f.name)).Hash.ToLower() -ne $f.new_sha256){throw 'Modified mismatch'}}
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $tx 'ROLLBACK.ps1')
if($LASTEXITCODE -ne 0){throw 'Standalone rollback failed'}
foreach($f in $manifest){if((Get-FileHash (Join-Path $install.FullName $f.name)).Hash.ToLower() -ne $f.old_sha256){throw 'Rollback mismatch'}}
'PASS baseline -> modified -> rollback exact hashes'
# A post-apply third-state edit must be preserved, not overwritten by rollback.
[IO.File]::WriteAllText((Join-Path $install.FullName 'daemon.bin'),'EXTERNAL-EDIT')
$ErrorActionPreference='Continue'
try {
  & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $tx 'ROLLBACK.ps1') 2>&1 | Out-String | Out-Null
  $driftExit=$LASTEXITCODE
} finally { $ErrorActionPreference='Stop' }
if($driftExit -eq 0){throw 'Drift accepted'}
if([IO.File]::ReadAllText((Join-Path $install.FullName 'daemon.bin')) -ne 'EXTERNAL-EDIT'){throw 'Drift overwritten'}
'PASS third-state drift refused'
# Restore fixture bytes, then reapply to a fresh transaction for ACL preflight.
[IO.File]::WriteAllText((Join-Path $install.FullName 'daemon.bin'),'BASELINE-daemon.bin')
$txAcl=Join-Path $w 'acl-transaction'
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Script -Mode Apply -InstallDir $install.FullName -TransactionDir $txAcl -ManifestPath $mp
if($LASTEXITCODE -ne 0){throw 'ACL setup apply failed'}
$second=Join-Path $install.FullName 'desktop.bin'
$originalAcl=Get-Acl $second
$changedAcl=Get-Acl $second
$changedAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),'Read','Allow'))
Set-Acl $second $changedAcl
if((Get-Acl $second).Sddl -eq $originalAcl.Sddl){throw 'ACL injection did not change ACL'}
$ErrorActionPreference='Continue'
try {
  & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $txAcl 'ROLLBACK.ps1') 2>&1 | Out-String | Out-Null
  $aclExit=$LASTEXITCODE
} finally { $ErrorActionPreference='Stop' }
if($aclExit -eq 0){throw 'ACL drift accepted'}
foreach($f in $manifest){if((Get-FileHash (Join-Path $install.FullName $f.name)).Hash.ToLower() -ne $f.new_sha256){throw 'ACL preflight modified file content'}}
'PASS second-file ACL drift refused before ANY file replacement'
Set-Acl $second $originalAcl
# Mixed pristine/modified recovery, using a native replacement to retain ACL.
$first=Join-Path $install.FullName 'daemon.bin'
$temp=$first+'.pristine'
[IO.File]::WriteAllText($temp,'BASELINE-daemon.bin')
[IO.File]::Replace($temp,$first,[System.Management.Automation.Language.NullString]::Value)
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $txAcl 'ROLLBACK.ps1')
if($LASTEXITCODE -ne 0){throw 'Mixed-state rollback failed'}
foreach($f in $manifest){if((Get-FileHash (Join-Path $install.FullName $f.name)).Hash.ToLower() -ne $f.old_sha256){throw 'Mixed-state mismatch'}}
'PASS mixed pristine/modified rollback'
# Lock second target against deletion, but allow reads/writes: preflight and
# snapshots work; its atomic replacement must fail AFTER first replacement.
$txFailure=Join-Path $w 'failure-transaction'
$before=@{}
foreach($f in $manifest){$p=Join-Path $install.FullName $f.name;$i=Get-Item $p;$before[$f.name]=@{sddl=(Get-Acl $p).Sddl;created=$i.CreationTimeUtc;modified=$i.LastWriteTimeUtc}}
$lock=[IO.File]::Open($second,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
try {
  $ErrorActionPreference='Continue'
  try {
    $failureOutput = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Script -Mode Apply -InstallDir $install.FullName -TransactionDir $txFailure -ManifestPath $mp 2>&1 | Out-String
    $failureExit=$LASTEXITCODE
  } finally { $ErrorActionPreference='Stop' }
} finally { $lock.Dispose() }
$failureOutput | Set-Content -Encoding UTF8 (Join-Path $w 'partial-failure.log')
if($failureExit -eq 0){throw 'Locked second replacement unexpectedly succeeded'}
if($failureOutput -notmatch 'REPLACED_FILE daemon.bin' -or $failureOutput -match 'REPLACED_FILE desktop.bin'){throw 'Failure did not occur after exactly the first file replacement'}
if($failureOutput -notmatch 'ROLLBACK_FILES_VERIFIED'){throw 'Automatic catch rollback did not complete'}
foreach($f in $manifest){
  $p=Join-Path $install.FullName $f.name;$i=Get-Item $p
  if((Get-FileHash $p).Hash.ToLower() -ne $f.old_sha256 -or (Get-Acl $p).Sddl -ne $before[$f.name].sddl -or $i.CreationTimeUtc -ne $before[$f.name].created -or $i.LastWriteTimeUtc -ne $before[$f.name].modified){throw 'Automatic rollback did not restore hash/ACL/timestamps'}
}
'PASS second-file locked Replace failure -> automatic rollback hash/ACL/timestamps; original nonzero retained'
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $txFailure 'ROLLBACK.ps1')
if($LASTEXITCODE -ne 0){throw 'Repeated independent rollback failed'}
'PASS independent rollback repeat after failed Apply'
"FIXTURE=$w"
