param([switch]$LibraryOnly)
$ErrorActionPreference='Stop'
function PlainPath([string]$p){if($p.StartsWith('\\?\UNC\')){return '\\'+$p.Substring(8)};if($p.StartsWith('\\?\')){return $p.Substring(4)};return $p}
function Decision($s){
 if(!$s.exists){return @{skip=$false;reason='no-own-update'}}
 if($s.terminal){return @{skip=$false;reason='known-terminal'}}
 if($s.installer_pid -gt 0){
  if($s.installer_state -in @('gone','reused')){return @{skip=$false;reason=('installer-'+$s.installer_state)}}
  return @{skip=$true;reason=('installer-'+$s.installer_state)}
 }
 if($s.authorized){return @{skip=$true;reason='authorized-installer-unknown'}}
 if($s.owner_state -in @('alive','unknown')){return @{skip=$true;reason=('owner-'+$s.owner_state)}}
 # Both owner readiness/authorization waits are 30 seconds. A dead,
 # pre-installer owner must not disable the always-online task forever.
 if($s.age_seconds -le 60){return @{skip=$true;reason='fresh-preparing'}}
 return @{skip=$false;reason='stale-preparing-no-live-owner'}
}
function ReadState([string]$journal,[string]$daemon){
 $pointer=Join-Path $journal 'install-owner-active.json'
 if(!(Test-Path -LiteralPath $pointer)){return @{exists=$false}}
 $dir=PlainPath ([IO.File]::ReadAllText($pointer,[Text.Encoding]::UTF8)|ConvertFrom-Json)
 # Successful installers remove their private TEMP tree. The durable outcome
 # is usable only for this exact staging parent, after this pointer was written.
 if(!(Test-Path -LiteralPath $dir)){
  $v=[IO.File]::ReadAllText((Join-Path $journal 'last-install.json'),[Text.Encoding]::UTF8)|ConvertFrom-Json
  $pointerTime=([DateTimeOffset](Get-Item -Force -LiteralPath $pointer).LastWriteTimeUtc).ToUnixTimeSeconds()
  if($v.status -cne 'SucceededVerified' -or $v.installer_exit_code -notin @(0,3010) -or !$v.finished_unix -or $v.finished_unix -lt $v.started_unix -or $v.started_unix -lt $pointerTime -or (PlainPath $v.new_binary_path) -ine $daemon -or $v.expected_version -notmatch '^agent-v[0-9]+\.[0-9]+\.[0-9]+$' -or $v.new_binary_version -cne ('meshharbord '+$v.expected_version.Substring(7)) -or (Split-Path $dir -Leaf) -notlike 'install-owner-*' -or (Split-Path $dir -Parent) -ine (Split-Path (PlainPath $v.installer_path) -Parent)){throw 'missing owner TEMP lacks exact durable success'}
  $active=@(Get-CimInstance Win32_Process | Where-Object {$_.Name -match '^meshharbord-(owner|watch[^.]*)[.]exe$' -or $_.CommandLine -match 'post-install-(owner|watch)' -or ($_.Name -ieq 'msiexec.exe' -and (!$_.CommandLine -or $_.CommandLine -notmatch '^"?C:\\Windows\\System32\\msiexec[.]exe"? /V$'))})
  if($active.Count){throw 'missing owner TEMP has active or unknown installer/owner'}
  return @{exists=$true;terminal=$true}
 }
 $requestPath=Join-Path $dir 'request.json';$r=[IO.File]::ReadAllText($requestPath,[Text.Encoding]::UTF8)|ConvertFrom-Json
 if((PlainPath $r.origin) -ine $daemon){return @{exists=$false}}
 $start=(Get-Item -Force -LiteralPath $requestPath).LastWriteTimeUtc
 $s=@{exists=$true;terminal=$false;installer_pid=0;installer_state='unknown';owner_state='gone';authorized=(Test-Path -LiteralPath (Join-Path $dir 'authorize.json'));age_seconds=([DateTime]::UtcNow-$start).TotalSeconds}
 $terminal=Join-Path $dir 'terminal.json'
 if(Test-Path -LiteralPath $terminal){
  $done=[IO.File]::ReadAllText($terminal,[Text.Encoding]::UTF8)|ConvertFrom-Json
  if($done.finished_unix -and $null -ne $done.installer_exit_code -and $done.status -notin @('InProgress','Timeout') -and $done.expected_version -ceq $r.expected_version -and $done.installer_path -ceq $r.installer){$s.terminal=$true;return $s}
 }
 $started=Join-Path $dir 'started.json'
 if(Test-Path -LiteralPath $started){$s.installer_pid=[uint32]([IO.File]::ReadAllText($started)|ConvertFrom-Json);$upper=(Get-Item -Force -LiteralPath $started).LastWriteTimeUtc.AddSeconds(2)}
 else{
  $ordinary=Join-Path $journal 'last-install.json'
  if(Test-Path -LiteralPath $ordinary){$v=[IO.File]::ReadAllText($ordinary)|ConvertFrom-Json;if($v.installer_path -ceq $r.installer -and $v.expected_version -ceq $r.expected_version){$s.installer_pid=[uint32]$v.installer_pid;$upper=(Get-Item -Force -LiteralPath $ordinary).LastWriteTimeUtc.AddSeconds(2)}}
 }
 if($s.installer_pid -gt 0){
  $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$s.installer_pid)
  if(!$p){$s.installer_state='gone'}
  elseif($p.Name -ine 'msiexec.exe' -or $p.CreationDate.ToUniversalTime() -lt $start.AddSeconds(-2) -or $p.CreationDate.ToUniversalTime() -gt $upper){$s.installer_state='reused'}
  elseif($p.CommandLine){$s.installer_state=if($p.CommandLine.Replace('\\?\','').ToLowerInvariant().Contains((PlainPath $r.installer).ToLowerInvariant())){'alive'}else{'reused'}}
  return $s
 }
 $ready=Join-Path $dir 'ready.json'
 if(Test-Path -LiteralPath $ready){
  $owner=[uint32]([IO.File]::ReadAllText($ready)|ConvertFrom-Json);$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$owner)
  if($p){
   if($p.Name -ine 'meshharbord-owner.exe' -or $p.CreationDate.ToUniversalTime() -lt $start.AddSeconds(-2)){$s.owner_state='reused'}
   elseif(!$p.CommandLine){$s.owner_state='unknown'}
   elseif($p.CommandLine.Replace('\\?\','').ToLowerInvariant().Contains($dir.ToLowerInvariant())){$s.owner_state='alive'}
   else{$s.owner_state='reused'}
  }
 }
 return $s
}
if($LibraryOnly){return}
$log=Join-Path $PSScriptRoot 'surface-update-launch-guard.log'
try{
 if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-21-1334683234-3010729374-3581155741-1001'){throw 'wrong launcher identity'}
 $state=ReadState (Join-Path $env:LOCALAPPDATA 'meshharbor\meshharbor\data\logs') 'C:\Users\jesus\AppData\Local\Programs\MeshHarbor\meshharbord.exe'
 $decision=Decision $state
}catch{$decision=@{skip=$true;reason='unknown-read-error';error=$_.Exception.Message}}
$decision.time=[DateTime]::UtcNow.ToString('o')
try{[IO.File]::AppendAllText($log,($decision|ConvertTo-Json -Compress)+[Environment]::NewLine,[Text.Encoding]::UTF8)}catch{exit 10}
if($decision.skip){exit 10};exit 0
