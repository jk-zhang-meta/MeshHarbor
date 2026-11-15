param([switch]$LibraryOnly)
$ErrorActionPreference='Stop'
function New-SurfaceKeepaliveXml([string]$original,[string]$launcher){
 [xml]$x=$original
 $ns=New-Object Xml.XmlNamespaceManager($x.NameTable);$ns.AddNamespace('t',$x.DocumentElement.NamespaceURI)
 $principal=$x.SelectSingleNode('/t:Task/t:Principals/t:Principal',$ns)
 if($principal.UserId -cne 'S-1-5-21-1334683234-3010729374-3581155741-1001' -or $principal.LogonType -cne 'InteractiveToken'){throw 'wrong principal'}
 $a=$x.SelectSingleNode('/t:Task/t:Actions/t:Exec',$ns)
 if($x.SelectNodes('/t:Task/t:Actions/*',$ns).Count -ne 1 -or $a.Command -cne '%SystemRoot%\System32\conhost.exe' -or $a.Arguments -cne '--headless "C:\Users\jesus\AppData\Local\Programs\MeshHarbor\meshharbord.exe" run --supervisor task'){throw 'unexpected action'}
 if($x.SelectSingleNode('/t:Task/t:Settings/t:MultipleInstancesPolicy',$ns).InnerText -cne 'IgnoreNew'){throw 'unexpected multiple instance policy'}
 if($x.SelectSingleNode('/t:Task/t:Triggers/t:TimeTrigger',$ns)){throw 'unexpected existing time trigger'}
 $a.Command='%SystemRoot%\System32\wscript.exe';$a.Arguments='//B //Nologo "'+$launcher+'"'
 $n=$x.DocumentElement.NamespaceURI;$trigger=$x.CreateElement('TimeTrigger',$n)
 $repeat=$x.CreateElement('Repetition',$n);$interval=$x.CreateElement('Interval',$n);$interval.InnerText='PT1M';[void]$repeat.AppendChild($interval);$stop=$x.CreateElement('StopAtDurationEnd',$n);$stop.InnerText='false';[void]$repeat.AppendChild($stop);[void]$trigger.AppendChild($repeat)
 $start=$x.CreateElement('StartBoundary',$n);$start.InnerText='2026-11-01T00:00:00';[void]$trigger.AppendChild($start)
 $enabled=$x.CreateElement('Enabled',$n);$enabled.InnerText='true';[void]$trigger.AppendChild($enabled)
 [void]$x.SelectSingleNode('/t:Task/t:Triggers',$ns).AppendChild($trigger)
 return $x.OuterXml
}
if(!$LibraryOnly){throw 'Library only: deploy through reviewed exact-task transaction'}
