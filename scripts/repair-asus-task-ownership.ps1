param([Parameter(Mandatory=$true)][ValidateSet('apply','rollback')][string]$Operation,
      [Parameter(Mandatory=$true)][string]$OldSddl)
$ErrorActionPreference='Stop'
$sid='S-1-5-21-436327934-2407261700-2341705934-1001'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $sid){throw 'wrong host account'}
function Identity([string]$s){
 $sd=New-Object Security.AccessControl.RawSecurityDescriptor($s)
 $aces=@();foreach($a in $sd.DiscretionaryAcl){
  if([int]$a.AceType -ne 0){throw 'unexpected non-allow ACE'}
  $bytes=New-Object byte[] $a.BinaryLength;$a.GetBinaryForm($bytes,0);$aces+=[Convert]::ToBase64String($bytes)
 }
 $flags=[int]$sd.ControlFlags -band (-bnot [int][Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited)
 return (@($sd.Owner.Value,$sd.Group.Value,$flags)+@($aces|Sort-Object)) -join '|'
}
function XmlIdentity([string]$xml){
 $d=[xml]$xml;$ns=New-Object Xml.XmlNamespaceManager($d.NameTable);$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
 $n=$d.SelectSingleNode('/t:Task/t:RegistrationInfo/t:SecurityDescriptor',$ns)
 if($n){$n.ParentNode.RemoveChild($n)|Out-Null};return $d.OuterXml
}
$sd=New-Object Security.AccessControl.RawSecurityDescriptor($OldSddl)
if($sd.Owner.Value -cne 'S-1-5-32-544' -or $sd.SystemAcl){throw 'unexpected original owner/SACL'}
$matches=0;$creatorOwner=0
for($i=0;$i -lt $sd.DiscretionaryAcl.Count;$i++){
 $a=$sd.DiscretionaryAcl[$i]
 if($a.SecurityIdentifier.Value -ceq $sid){
  if([int]$a.AceType -ne 0 -or [int]$a.AceFlags -ne 0 -or $a.AccessMask -ne 0x120089){throw 'unexpected existing user permission'}
  $sd.DiscretionaryAcl[$i]=New-Object Security.AccessControl.CommonAce($a.AceFlags,$a.AceQualifier,0x1f01ff,$a.SecurityIdentifier,$false,$null)
  $matches++
 }
 if($a.SecurityIdentifier.Value -ceq 'S-1-5-32-544' -and [int]$a.AceFlags -eq 16 -and $a.AccessMask -eq 0x1f01ff){
  # The Tasks parent has inheritable CREATOR_OWNER full control. Windows
  # substitutes the new owner here; retain BA's old effective full rights
  # with one explicit compensating ACE, not a protected DACL.
  $sd.DiscretionaryAcl[$i]=New-Object Security.AccessControl.CommonAce($a.AceFlags,$a.AceQualifier,$a.AccessMask,(New-Object Security.Principal.SecurityIdentifier($sid)),$false,$null)
  $creatorOwner++
 }
}
if($matches -ne 1 -or $creatorOwner -ne 1){throw 'unexpected user/creator-owner ACE layout'}
$ba=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$sd.DiscretionaryAcl.InsertAce(1,(New-Object Security.AccessControl.CommonAce([Security.AccessControl.AceFlags]::None,[Security.AccessControl.AceQualifier]::AccessAllowed,0x1f01ff,$ba,$false,$null)))
$sd.Owner=New-Object Security.Principal.SecurityIdentifier($sid)
$new=$sd.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
$expected=if($Operation -eq 'apply'){$OldSddl}else{$new}
$desired=if($Operation -eq 'apply'){$new}else{$OldSddl}
$path='C:\Windows\System32\Tasks\MeshHarbor'
if((Get-Item -Force -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'task reparse'}
if((Identity (Get-Acl -LiteralPath $path).Sddl) -cne (Identity $expected)){throw 'task ACL third state'}
$s=New-Object -ComObject Schedule.Service;$s.Connect();$folder=$s.GetFolder('\');$task=$folder.GetTask('MeshHarbor')
if($task.Path -cne '\MeshHarbor'){throw 'wrong task'}
$xml=XmlIdentity $task.Xml;$enabled=$task.Enabled
# Native Task Scheduler metadata API only: no register, stop, start or XML write.
$task.SetSecurityDescriptor($desired,16)
$observed=$folder.GetTask('MeshHarbor')
if((Identity (Get-Acl -LiteralPath $path).Sddl) -cne (Identity $desired) -or (XmlIdentity $observed.Xml) -cne $xml -or $observed.Enabled -ne $enabled){throw 'task metadata readback differs'}
@{operation=$Operation;task=$observed.Path;old=$expected;new=(Get-Acl -LiteralPath $path).Sddl;xml_unchanged=$true;enabled=$observed.Enabled}|ConvertTo-Json -Compress
