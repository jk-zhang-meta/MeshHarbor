Option Explicit
' Exact-user launcher. Task Scheduler remains the only restart supervisor.
' No console window, no shell profile, no credential or privilege changes.
Dim shell, quote, daemon, command, result, guard
Set shell = CreateObject("WScript.Shell")
quote = Chr(34)
guard = quote & "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" & quote & " -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " & quote & "C:\Users\jesus\AppData\Local\MeshHarborRecovery\account-merge-20261114\asus-update-launch-guard.ps1" & quote
If shell.Run(guard, 0, True) <> 0 Then WScript.Quit 0
daemon = "C:\Users\jesus\AppData\Local\Programs\MeshHarbor\meshharbord.exe"
command = quote & "C:\Windows\System32\cmd.exe" & quote & " /d /s /c " & quote & quote & daemon & quote & " run --supervisor task >NUL 2>NUL" & quote
result = shell.Run(command, 0, True)
WScript.Quit result
