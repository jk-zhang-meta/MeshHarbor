# Run with Windows PowerShell 5.1 or pwsh. No installation, elevation, network,
# daemon, or firewall command is executed: Start-Process is a recording mock.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot 'install.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }

$initialize = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Initialize-DaemonFirewall'
}, $true)
if (-not $initialize) { throw 'missing installer firewall preparation' }
. ([scriptblock]::Create($initialize.Extent.Text))

function Say([string]$Message) {}
$script:Elevated = $false
$script:NextExit = 0
$script:Calls = @()
$AllowPublicFirewall = $false
function Test-Elevated { $script:Elevated }
function Start-Process {
    param($FilePath, $Verb, $WindowStyle, [string[]]$ArgumentList, [switch]$Wait, [switch]$PassThru)
    $script:Calls += [pscustomobject]@{
        FilePath = $FilePath; Verb = $Verb; Args = $ArgumentList
        Wait = [bool]$Wait; PassThru = [bool]$PassThru
    }
    [pscustomobject]@{ ExitCode = $script:NextExit }
}

$daemon = 'C:\Users\standard user\Programs\MeshHarbor\meshharbord.exe'
Initialize-DaemonFirewall -Daemon $daemon
if ($script:Calls.Count -ne 1) { throw 'expected exactly one bounded elevation' }
$call = $script:Calls[0]
if ($call.FilePath -ne $daemon -or $call.Verb -ne 'RunAs' -or
    ($call.Args -join ' ') -ne 'service prepare-firewall' -or
    -not $call.Wait -or -not $call.PassThru) {
    throw 'elevation must run only the installed daemon firewall command and wait for its result'
}

$script:NextExit = 5
$refused = $false
try { Initialize-DaemonFirewall -Daemon $daemon } catch { $refused = $true }
if (-not $refused) { throw 'a failed firewall command must abort before enrollment/autostart' }

$script:NextExit = 0
$AllowPublicFirewall = $true
Initialize-DaemonFirewall -Daemon $daemon
if (($script:Calls[-1].Args -join ' ') -ne 'service prepare-firewall --allow-public') {
    throw 'Public requires the explicit opt-in argument'
}
$AllowPublicFirewall = $false

$script:Elevated = $true
$script:Calls = @()
function Test-Daemon { $global:LASTEXITCODE = 0 }
Initialize-DaemonFirewall -Daemon 'Test-Daemon'
if ($script:Calls.Count) { throw 'an elevated caller must not launch another elevation' }

$install = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Install-Daemon'
}, $true).Extent.Text
$prep = $install.IndexOf('Initialize-DaemonFirewall -Daemon $daemon')
if ($prep -lt 0 -or $prep -gt $install.IndexOf('$enrollArgs =') -or
    $prep -gt $install.IndexOf('Install-Desktop -InstallDir')) {
    throw 'prepare the firewall before enrollment, companion installation, and autostart'
}
if ($prep -lt $install.IndexOf("if (`$DownloadOnly)")) {
    throw 'download-only must return without elevation or firewall mutations'
}
if ($install.IndexOf('MESH_SKIP_AUTOSTART=1') -gt $install.IndexOf("Start-Process -FilePath 'msiexec.exe'")) {
    throw 'defer fresh-install autostart before invoking the MSI'
}
[xml]$wix = Get-Content -Raw (Join-Path $PSScriptRoot '..\agents\roomlerd\wix\main.wxs')
$ns = [System.Xml.XmlNamespaceManager]::new($wix.NameTable)
$ns.AddNamespace('w', 'http://schemas.microsoft.com/wix/2006/wi')
$condition = $wix.SelectSingleNode("//w:Custom[@Action='RegisterAutostart']", $ns).InnerText
if ($condition -notmatch 'NOT MESH_SKIP_AUTOSTART') {
    throw 'MSI must honor deferred autostart when firewall preparation may be cancelled'
}
$removal = $wix.SelectSingleNode("//w:Custom[@Action='RemoveInstallFirewall']", $ns).InnerText
if ($removal -notmatch 'NOT UPGRADINGPRODUCTCODE') {
    throw 'upgrades must preserve the same-path firewall rules without another approval'
}
$removalAction = $wix.SelectSingleNode("//w:CustomAction[@Id='RemoveInstallFirewall']", $ns)
if ($removalAction.Return -ne 'ignore') {
    throw 'firewall cancellation/failure must not block MSI uninstall'
}
Write-Output 'PASS: PS parser, bounded elevation, failure propagation, elevated caller, install ordering, MSI autostart deferral, nonblocking uninstall'
