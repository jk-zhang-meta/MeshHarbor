param([Parameter(Mandatory=$true)][string]$Implementation,
      [Parameter(Mandatory=$true)][string]$RuntimeRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Join-Path $RuntimeRoot ('msi-path-fixture-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
# Only redirect the fixed journal base in this private fixture. Production has
# no path parameter; all tested functions otherwise use the exact source bytes.
$text=[IO.File]::ReadAllText($Implementation)
$needle="`$base = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MeshHarbor\InstallerTransactions'"
if(($text.Split(@($needle),[StringSplitOptions]::None)).Count -ne 2){throw 'fixture substitution mismatch'}
Invoke-Expression ($text.Replace($needle,'$base = $script:FixtureBase'))
$outside=Join-Path $root 'outside'
New-Item -ItemType Directory -Path $outside | Out-Null
$marker=Join-Path $outside 'marker.json'
[IO.File]::WriteAllText($marker,'{"unchanged":true}')
function Target-Identity {
 $entries=@(Get-Item -LiteralPath $outside)+@(Get-ChildItem -LiteralPath $outside -Recurse -Force)
 return (@($entries | Sort-Object FullName | ForEach-Object {
  $hash='directory'; if(-not $_.PSIsContainer){$hash=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
  $_.FullName+'|'+$hash+'|'+(Get-Acl -LiteralPath $_.FullName).Sddl
 }) -join "`n")
}
function Assert-Rejected([string]$Label,[scriptblock]$Operation) {
 $before=Target-Identity
 $rejected=$false
 try { & $Operation } catch { $rejected=$_.Exception.Message -like '*reparse point*' }
 if(-not $rejected){throw "$Label did not reject the reparse point"}
 if((Target-Identity) -cne $before){throw "$Label changed external target content/ACL"}
 Write-Output "PASS: $Label rejected; target content, entries and ACL unchanged"
}
$product='{'+[Guid]::NewGuid().ToString().ToUpperInvariant()+'}'
$name='MeshHarbor-PathFixture-'+[Guid]::NewGuid().ToString('N')
$junction=Join-Path $root 'ancestor-link'
$pointerLink=$null;$journalLink=$null;$nonceLink=$null;$danglingLink=$null
try {
 New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
 Assert-Rejected 'ancestor junction before mkdir/ACL' {New-PrivateDirectory (Join-Path $junction 'new-leaf')}
 Assert-Rejected 'leaf junction before ACL' {New-PrivateDirectory $junction}
 $script:FixtureBase=Join-Path $junction 'InstallerTransactions'
 Assert-Rejected 'fixed base ancestor before snapshot' {Invoke-TaskTransaction 'snapshot' $product '' @($name)}

 $script:FixtureBase=Join-Path $root 'state';New-PrivateDirectory $script:FixtureBase
 $pointerLink=Join-Path $script:FixtureBase ($product+'.json')
 New-Item -ItemType SymbolicLink -Path $pointerLink -Target $marker | Out-Null
 Assert-Rejected 'pointer file link before read' {Invoke-TaskTransaction 'rollback' $product '' @($name)}
 [IO.File]::Delete($pointerLink);$pointerLink=$null

 $nonce=[Guid]::NewGuid().ToString('N');$nonceDir=Join-Path $script:FixtureBase $nonce;New-PrivateDirectory $nonceDir
 $journalLink=Join-Path $nonceDir 'tasks.json'
 New-Item -ItemType SymbolicLink -Path $journalLink -Target $marker | Out-Null
 $pointer=Join-Path $script:FixtureBase ($product+'.json')
 Write-NewJson $pointer @{nonce=$nonce;sha256=(Get-FileHash $marker -Algorithm SHA256).Hash}
 Assert-Rejected 'journal file link before hash/read' {Invoke-TaskTransaction 'rollback' $product '' @($name)}
 [IO.File]::Delete($journalLink);$journalLink=$null;[IO.File]::Delete($pointer)

 $nonce=[Guid]::NewGuid().ToString('N');$nonceLink=Join-Path $script:FixtureBase $nonce
 New-Item -ItemType Junction -Path $nonceLink -Target $outside | Out-Null
 Write-NewJson $pointer @{nonce=$nonce;sha256='unused'}
 Assert-Rejected 'nonce directory junction before journal read' {Invoke-TaskTransaction 'rollback' $product '' @($name)}
 [IO.File]::Delete($pointer)

 $danglingLink=$pointer
 $missing=Join-Path $outside 'does-not-exist.json'
 [IO.File]::WriteAllText($missing,'fixture')
 New-Item -ItemType SymbolicLink -Path $danglingLink -Target $missing | Out-Null
 [IO.File]::Delete($missing)
 Assert-Rejected 'dangling pointer link' {Invoke-TaskTransaction 'rollback' $product '' @($name)}
} finally {
 foreach($link in @($pointerLink,$journalLink,$danglingLink)){if($link){[IO.File]::Delete($link)}}
 foreach($link in @($junction,$nonceLink)){if($link -and (Test-Path -LiteralPath $link)){& cmd.exe /d /c "rmdir `"$link`"";if($LASTEXITCODE -ne 0){throw 'junction cleanup failed'}}}
}
Write-Output "Fixture artifacts: $root; all links removed; no real task accessed"
