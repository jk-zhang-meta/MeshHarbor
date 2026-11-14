param([Parameter(Mandatory=$true)][string]$Guard)
$ErrorActionPreference='Stop'
. $Guard -LibraryOnly
$root=Join-Path $env:TEMP ('mh-launch-guard-fixture-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root)|Out-Null
function WriteJson($p,$v){[IO.File]::WriteAllText($p,($v|ConvertTo-Json -Compress),[Text.Encoding]::UTF8)}
function Check($name,$expected){$d=Decision (ReadState $root 'C:\fixture\meshharbord.exe');if($d.skip -ne $expected){throw ($name+': '+($d|ConvertTo-Json))};Write-Output ($name+' PASS '+$d.reason)}
function Get-CimInstance {param($ClassName,$Filter);return $script:process}
try{
 Check 'no-update' $false
 $dir=Join-Path $root 'owner';[IO.Directory]::CreateDirectory($dir)|Out-Null
 WriteJson (Join-Path $root 'install-owner-active.json') $dir
 $request=@{origin='\\?\C:\fixture\meshharbord.exe';installer='\\?\C:\fixture\package.msi';expected_version='agent-v0.4.160'}
 $requestPath=Join-Path $dir 'request.json';WriteJson $requestPath $request
 $script:process=$null
 Check 'fresh-preparing' $true
 (Get-Item $requestPath).LastWriteTimeUtc=[DateTime]::UtcNow.AddMinutes(-5)
 Check 'stale-preparing' $false
 WriteJson (Join-Path $dir 'ready.json') 123
 $script:process=[pscustomobject]@{Name='meshharbord-owner.exe';CreationDate=[DateTime]::UtcNow.AddMinutes(-4);CommandLine=('owner '+$dir)}
 Check 'live-owner-preparing' $true
 $script:process.CommandLine=$null;Check 'stale-owner-command-unreadable' $true
 $script:process=$null;WriteJson (Join-Path $dir 'authorize.json') 123
 Check 'authorized-no-installer-pid-dead-owner' $true
 WriteJson (Join-Path $dir 'started.json') 456
 $script:process=[pscustomobject]@{Name='msiexec.exe';CreationDate=[DateTime]::UtcNow.AddSeconds(-1);CommandLine='msiexec /i "C:\fixture\package.msi"'}
 Check 'own-installer-active' $true
 $script:process.CommandLine='msiexec /i "\\?\C:\fixture\package.msi"';Check 'canonical-command' $true
 $script:process.CommandLine=$null;Check 'unreadable-own-pid' $true
 $script:process=$null;Check 'installer-gone-liveverify-allowed' $false
 $script:process=[pscustomobject]@{Name='msiexec.exe';CreationDate=[DateTime]::UtcNow.AddMinutes(1);CommandLine='msiexec /i "C:\fixture\package.msi"'}
 Check 'pid-reused' $false
 $script:process.CreationDate=[DateTime]::UtcNow.AddSeconds(-1);$script:process.CommandLine='msiexec /i "C:\unrelated.msi"';Check 'unrelated-msi' $false
 WriteJson (Join-Path $dir 'terminal.json') @{finished_unix=123;installer_exit_code=1603;status='InstallerFailed';expected_version=$request.expected_version;installer_path=$request.installer}
 Check 'known-terminal' $false
 Write-Output 'ALL 13 FIXTURES PASS; NO INSTALLER OR TASK MUTATION'
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
