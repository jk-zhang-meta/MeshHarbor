param([Parameter(Mandatory=$true)][string]$Implementation,
      [Parameter(Mandatory=$true)][string]$FixtureRoot,
      [switch]$RequireFilteredToken)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. $Implementation
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($RequireFilteredToken -and $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Fixture must run with a non-elevated token'
}
$path = Join-Path $FixtureRoot ('private-acl-' + [Guid]::NewGuid().ToString('N'))
try {
    foreach ($iteration in @(1,2)) {
        New-PrivateDirectory $path
        $acl = (Get-Item -LiteralPath $path).GetAccessControl()
        if (!$acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $identity.User.Value) { throw 'owner/protection mismatch' }
        $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
        if ($rules.Count -ne 2) { throw 'unexpected access grant' }
        foreach ($rule in $rules) {
            if ($rule.IdentityReference.Value -notin @($identity.User.Value,'S-1-5-18') -or
                $rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or
                $rule.FileSystemRights -ne 'FullControl' -or
                $rule.InheritanceFlags -ne 'ContainerInherit,ObjectInherit' -or
                $rule.PropagationFlags -ne 'None') { throw 'private ACL broadened' }
        }
        [IO.File]::WriteAllText((Join-Path $path 'probe.txt'),'private fixture')
        Write-Output "PASS: iteration $iteration exact protected owner/SYSTEM-only ACL and writable directory"
    }
    Write-Output ('PASS: filtered=' + !$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
} finally {
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
}
