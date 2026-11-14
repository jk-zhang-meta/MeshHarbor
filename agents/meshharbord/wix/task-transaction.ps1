# MSI per-user task transaction. Invoked only by the embedded native helper.
# Task Scheduler COM retains XML and DACL; no text parsing of localized schtasks errors.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ExistingTask($Folder, [string]$Name) {
    try { return $Folder.GetTask($Name) }
    catch {
        if ($_.Exception.HResult -eq -2147024894) { return $null } # ERROR_FILE_NOT_FOUND only
        throw
    }
}
function Assert-NoReparsePath([string]$Path) {
    # Walk root first: checking only the leaf can already traverse a junction
    # before CreateDirectory/Set-Acl. Missing suffixes may be created; access
    # failures are not absence. Get-Item also exposes dangling reparse entries.
    $full = [IO.Path]::GetFullPath($Path)
    $parts = New-Object 'Collections.Generic.List[string]'
    for ($part = $full; -not [string]::IsNullOrEmpty($part); $part = [IO.Path]::GetDirectoryName($part)) {
        $parts.Add($part)
    }
    for ($i = $parts.Count - 1; $i -ge 0; $i--) {
        try { $item = Get-Item -LiteralPath $parts[$i] -Force -ErrorAction Stop }
        catch [Management.Automation.ItemNotFoundException] { break }
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Refusing a reparse point in the transaction path'
        }
    }
}
function New-PrivateDirectory([string]$Path) {
    Assert-NoReparsePath $Path
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($who in @($sid, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($who, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
    Assert-NoReparsePath $Path
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Write-NewJson([string]$Path, $Value) {
    Assert-NoReparsePath $Path
    $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 12 -Compress))
    $f = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $f.Write($bytes, 0, $bytes.Length); $f.Flush($true) } finally { $f.Dispose() }
}
function Get-AclIdentity([string]$Sddl) {
    $sd = New-Object Security.AccessControl.RawSecurityDescriptor($Sddl)
    $common = New-Object Security.AccessControl.CommonSecurityDescriptor($false, $false, $Sddl)
    $aces = @()
    $allowOnly = $true
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ([int]$ace.AceType -notin @(0,5)) { $allowOnly = $false }
        $bytes = New-Object byte[] $ace.BinaryLength
        $ace.GetBinaryForm($bytes,0)
        $aces += [Convert]::ToBase64String($bytes)
    }
    if (-not $allowOnly -and -not $common.IsDiscretionaryAclCanonical) {
        throw 'Noncanonical mixed-deny ACL cannot be losslessly restored; upgrade refused'
    }
    # All-Allow ACEs commute. Do not reorder a mixed allow/deny ACL. Scheduler
    # canonicalizes all-Allow inherited/explicit order and sets AI on restore;
    # AI is bookkeeping, while protected/inherited ACE flags remain checked.
    if ($allowOnly) { $aces = @($aces | Sort-Object) }
    $flags = [int]$sd.ControlFlags -band (-bnot [int][Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited)
    return (@($sd.Owner.Value, $sd.Group.Value, $flags) + $aces) -join '|'
}
function Get-TaskSnapshot($Task, [string]$Name) {
    $definition = $Task.Definition
    $logon = [int]$definition.Principal.LogonType
    # Password and InteractiveTokenOrPassword cannot be reconstructed from exported XML.
    if ($logon -eq 1 -or $logon -eq 6) { throw "Task $Name requires an unavailable password; upgrade refused" }
    $sddl = [string]$Task.GetSecurityDescriptor(7)
    Get-AclIdentity $sddl | Out-Null
    # Scheduler's GetSecurityDescriptor omits DACL protection and can synthesize
    # a principal read ACE. Read the documented backing task-file ACL as well;
    # never write it directly. If unavailable, fail before old-product removal.
    $taskFile = Join-Path (Join-Path $env:SystemRoot 'System32\Tasks') ([string]$Task.Path).TrimStart('\')
    $fileSddl = (Get-Acl -LiteralPath $taskFile).Sddl
    Get-AclIdentity $fileSddl | Out-Null
    return @{ name=$Name; xml=[string]$Task.Xml; sddl=$sddl; file_sddl=$fileSddl;
              enabled=[bool]$Task.Enabled; running=([int]$Task.State -eq 4); logon=$logon }
}
function Get-TaskXmlIdentity([string]$Xml) {
    $doc = [xml]$Xml
    $ns = New-Object Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
    # Scheduler inserts the live security descriptor into exported registration
    # metadata on import. Check the actual ACL separately, not stale XML metadata.
    $node = $doc.SelectSingleNode('/t:Task/t:RegistrationInfo/t:SecurityDescriptor',$ns)
    if ($null -ne $node) { $node.ParentNode.RemoveChild($node) | Out-Null }
    return $doc.OuterXml
}
function Restore-Snapshot($Folder, $Entry) {
    $definition = $script:Scheduler.NewTask(0)
    $definition.XmlText = [string]$Entry.xml
    $principal = $definition.Principal
    $identity = [string]$principal.UserId
    if ([int]$Entry.logon -eq 4) { $identity = [string]$principal.GroupId }
    # CREATE_OR_UPDATE | DONT_ADD_PRINCIPAL_ACE, preserving the captured security descriptor.
    $task = $Folder.RegisterTaskDefinition([string]$Entry.name, $definition, 22, $identity, $null, [int]$Entry.logon, [string]$Entry.file_sddl)
    $task.Enabled = [bool]$Entry.enabled
    $task = $Folder.GetTask([string]$Entry.name)
    $observed = Get-TaskSnapshot $task ([string]$Entry.name)
    if ((Get-TaskXmlIdentity $observed.xml) -cne (Get-TaskXmlIdentity ([string]$Entry.xml)) -or
        (Get-AclIdentity $observed.file_sddl) -cne (Get-AclIdentity ([string]$Entry.file_sddl)) -or $observed.enabled -ne [bool]$Entry.enabled) {
        throw ('Task restore readback differs (XML={0}, ACL={1}, enabled={2}); recovery material retained' -f ((Get-TaskXmlIdentity $observed.xml) -ceq (Get-TaskXmlIdentity ([string]$Entry.xml))), ((Get-AclIdentity $observed.file_sddl) -ceq (Get-AclIdentity ([string]$Entry.file_sddl))), ($observed.enabled -eq [bool]$Entry.enabled))
    }
    return $task
}
function Invoke-TaskTransaction([string]$Operation, [string]$ProductCode, [string]$InstalledExe, [string[]]$Names = @('MeshHarbor', 'MeshHarborAgent')) {
    if ($ProductCode -notmatch '^\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$') { throw 'Invalid product code' }
    if ($Operation -notin @('snapshot','restore-or-create','rollback','start-if-enabled')) { throw 'Invalid transaction operation' }
    $base = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'MeshHarbor\InstallerTransactions'
    Assert-NoReparsePath $base
    if ($Operation -eq 'snapshot') { New-PrivateDirectory $base }
    $pointer = Join-Path $base ($ProductCode + '.json')
    Assert-NoReparsePath $pointer
    $script:Scheduler = New-Object -ComObject 'Schedule.Service'
    $script:Scheduler.Connect()
    $folder = $script:Scheduler.GetFolder('\')
    if ($Operation -eq 'snapshot') {
        if (Test-Path -LiteralPath $pointer) { throw 'An unfinished installer transaction exists; refusing to overwrite recovery material' }
        $entries = @()
        foreach ($name in $names) {
            $task = Get-ExistingTask $folder $name
            if ($null -ne $task) { $entries += Get-TaskSnapshot $task $name }
        }
        $nonce = [Guid]::NewGuid().ToString('N')
        $directory = Join-Path $base $nonce
        New-PrivateDirectory $directory
        $journal = Join-Path $directory 'tasks.json'
        Write-NewJson $journal @{ product=$ProductCode; sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; tasks=$entries }
        Write-NewJson $pointer @{ nonce=$nonce; sha256=(Get-FileHash -LiteralPath $journal -Algorithm SHA256).Hash }
        return
    }
    $link = Get-Content -LiteralPath $pointer -Raw | ConvertFrom-Json
    if ([string]$link.nonce -notmatch '^[0-9a-f]{32}$') { throw 'Invalid transaction identity' }
    $directory = Join-Path $base ([string]$link.nonce)
    Assert-NoReparsePath $directory
    $journal = Join-Path $directory 'tasks.json'
    Assert-NoReparsePath $journal
    if ((Get-FileHash -LiteralPath $journal -Algorithm SHA256).Hash -cne [string]$link.sha256) { throw 'Recovery material hash mismatch' }
    $saved = Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json
    if ($saved.product -cne $ProductCode -or $saved.sid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) { throw 'Transaction authority mismatch' }
    if ($Operation -eq 'restore-or-create') {
        if (@($saved.tasks).Count -eq 0) {
            & $InstalledExe service install
            if ($LASTEXITCODE -ne 0) { throw 'Fresh task registration failed' }
        } else {
            foreach ($entry in $saved.tasks) { Restore-Snapshot $folder $entry | Out-Null }
        }
        return
    }
    if ($Operation -eq 'rollback') {
        foreach ($name in $names) {
            $entry = @($saved.tasks | Where-Object { $_.name -ceq $name })
            if ($entry.Count -eq 0) {
                if ($null -ne (Get-ExistingTask $folder $name)) { $folder.DeleteTask($name, 0) }
            } else {
                $task = Restore-Snapshot $folder $entry[0]
                if ($entry[0].running -and $entry[0].enabled) { $task.Run($null) | Out-Null }
            }
        }
    } else {
        # Preserve a disabled task. An enabled installed task starts even when the
        # old updater exited cleanly. A start failure retains the only recovery copy.
        $startNames = @($saved.tasks | ForEach-Object { [string]$_.name })
        if ($startNames.Count -eq 0) { $startNames = @($Names[0]) }
        foreach ($name in $startNames) {
            $task = Get-ExistingTask $folder $name
            if ($null -eq $task) { throw 'Installed task missing before commit' }
            if ($task.Enabled) { $task.Run($null) | Out-Null }
        }
    }
    Assert-NoReparsePath $pointer
    Assert-NoReparsePath $journal
    Remove-Item -LiteralPath $pointer
    Remove-Item -LiteralPath $journal
    Remove-Item -LiteralPath $directory
}
