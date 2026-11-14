param([Parameter(Mandatory=$true)][string]$Implementation)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. $Implementation
$name = 'MeshHarbor-InstallerFixture-' + [Guid]::NewGuid().ToString('N')
$product = '{' + [Guid]::NewGuid().ToString().ToUpperInvariant() + '}'
$scheduler = New-Object -ComObject 'Schedule.Service'
$scheduler.Connect()
$folder = $scheduler.GetFolder('\')
$definition = $scheduler.NewTask(0)
# Construct Unicode by code point so this test source also loads correctly in PS5.
$unicode = ([string][char]0x2014) + ' ' + [char]0x4E2D + [char]0x6587 + ' ' + [char]0x00E9
$definition.RegistrationInfo.Description = 'Isolated fixture; never started ' + $unicode
$definition.RegistrationInfo.Author = 'Fixture user ' + $unicode
$definition.Principal.UserId = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$definition.Principal.LogonType = 3
$definition.Settings.Enabled = $false
$definition.Settings.Hidden = $true
$definition.Settings.DisallowStartIfOnBatteries = $false
$definition.Settings.StopIfGoingOnBatteries = $false
$definition.Settings.ExecutionTimeLimit = 'PT0S'
$trigger = $definition.Triggers.Create(9)
$trigger.UserId = $definition.Principal.UserId
$trigger.Repetition.Interval = 'PT1M'
$action = $definition.Actions.Create(0)
$action.Path = Join-Path $env:SystemRoot 'System32\wscript.exe'
$action.Arguments = '"C:\fixture only\' + $unicode + '\custom.vbs"'
$action.WorkingDirectory = 'C:\'
try {
    $task = $folder.RegisterTaskDefinition($name, $definition, 2, $definition.Principal.UserId, $null, 3, $null)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $task.SetSecurityDescriptor("D:P(D;;FW;;;S-1-5-21-0-0-0-1000)(A;;FA;;;SY)(A;;FA;;;$sid)",0)
    $before = Get-TaskSnapshot ($folder.GetTask($name)) $name
    Invoke-TaskTransaction 'snapshot' $product '' @($name)
    $folder.DeleteTask($name,0) # old MSI's uninstall
    Invoke-TaskTransaction 'restore-or-create' $product '' @($name)
    $after = Get-TaskSnapshot ($folder.GetTask($name)) $name
    if ((Get-TaskXmlIdentity $after.xml) -cne (Get-TaskXmlIdentity $before.xml) -or (Get-AclIdentity $after.file_sddl) -cne (Get-AclIdentity $before.file_sddl) -or $after.enabled) { throw 'custom/disabled task changed' }
    Invoke-TaskTransaction 'start-if-enabled' $product '' @($name)
    if ([int]$folder.GetTask($name).State -ne 1) { throw 'Disabled task was started' }
    Write-Output 'PASS: Unicode description/author/action path and custom WScript/PT1M/principal/disabled/XML/ACL preserved; disabled not started'

    $product = '{' + [Guid]::NewGuid().ToString().ToUpperInvariant() + '}'
    Invoke-TaskTransaction 'snapshot' $product '' @($name)
    $folder.DeleteTask($name,0)
    Invoke-TaskTransaction 'rollback' $product '' @($name)
    $after = Get-TaskSnapshot ($folder.GetTask($name)) $name
    if ((Get-TaskXmlIdentity $after.xml) -cne (Get-TaskXmlIdentity $before.xml) -or (Get-AclIdentity $after.file_sddl) -cne (Get-AclIdentity $before.file_sddl)) { throw 'rollback differs' }
    Write-Output 'PASS: rollback restores original XML and ACL'

    $folder.DeleteTask($name,0)
    if ($null -ne (Get-ExistingTask $folder $name)) { throw 'absence not recognized' }
    $product = '{' + [Guid]::NewGuid().ToString().ToUpperInvariant() + '}'
    Invoke-TaskTransaction 'snapshot' $product '' @($name)
    $folder.RegisterTaskDefinition($name, $definition, 2, $definition.Principal.UserId, $null, 3, $null) | Out-Null
    Invoke-TaskTransaction 'rollback' $product '' @($name)
    if ($null -ne (Get-ExistingTask $folder $name)) { throw 'fresh rollback left task behind' }
    Write-Output 'PASS: genuine absence and fresh rollback'

    $task = $folder.RegisterTaskDefinition($name, $definition, 2, [Security.Principal.WindowsIdentity]::GetCurrent().User.Value, $null, 3, $null)
    $beforeDefault = Get-TaskSnapshot $task $name
    $product = '{' + [Guid]::NewGuid().ToString().ToUpperInvariant() + '}'
    Invoke-TaskTransaction 'snapshot' $product '' @($name)
    $folder.DeleteTask($name,0)
    Invoke-TaskTransaction 'restore-or-create' $product '' @($name)
    $afterDefault = Get-TaskSnapshot ($folder.GetTask($name)) $name
    if ((Get-AclIdentity $afterDefault.file_sddl) -cne (Get-AclIdentity $beforeDefault.file_sddl)) { throw 'Default inherited ACL changed' }
    Invoke-TaskTransaction 'start-if-enabled' $product '' @($name)
    Write-Output 'PASS: default inherited All-Allow ACL retained'


    $fake = [pscustomobject]@{ Definition=[pscustomobject]@{ Principal=[pscustomobject]@{ LogonType=1 } } }
    $rejected=$false
    try { Get-TaskSnapshot $fake 'password fixture' | Out-Null } catch { $rejected=$_.Exception.Message -like '*password*' }
    if (-not $rejected) { throw 'password-backed task accepted' }
    Write-Output 'PASS: password task fails closed'
    $denied = New-Object PSObject
    $denied | Add-Member ScriptMethod GetTask { param($name) throw (New-Object Runtime.InteropServices.COMException('denied', -2147024891)) }
    $rejected = $false
    try { Get-ExistingTask $denied 'denied fixture' | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Access denied was treated as absence' }
    Write-Output 'PASS: access denied fails closed, never fresh-install'

} finally {
    $task = Get-ExistingTask $folder $name
    if ($null -ne $task) { $folder.DeleteTask($name,0) }
}
