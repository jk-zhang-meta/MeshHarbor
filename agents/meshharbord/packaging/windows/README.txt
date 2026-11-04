# RETIRED-NAME-ANCHOR-BEGIN
# Every retired name left in this file is ACCURATE and must stay:
#   * "Roomler Agent" IS the MSI ARP DisplayName (wix/main.wxs Name=)
#   * roomler-agent-<version>-…msi ARE the published asset filenames
#   * roomler-agent.exe IS the compatibility alias the MSI installs
# The service name, task name and config paths in here were NOT accurate and
# were corrected; this file ships to operators, so a wrong instruction here is
# a support ticket.
# INVARIANT: a retired name here must be one a user can actually see on their
# machine. docs/fr/FR-21
Roomler Agent — README
======================

The Roomler AI remote-control agent runs on this machine, maintains an
outbound WebSocket connection to the Roomler API, and (on demand) serves
a WebRTC peer directly to a browser controller. All screen video and
input events travel on that P2P channel — the Roomler server never sees
them.

Installation
------------
This installer placed the daemon `roomlerd.exe` (plus a
`roomler-agent.exe` compatibility alias and the `roomler` tunnel CLI)
at:

    %LOCALAPPDATA%\Programs\Roomler\roomlerd.exe
    %LOCALAPPDATA%\Programs\Roomler\roomler.exe

The install directory is appended to your user PATH, so `roomler`
and `roomlerd` work from any NEW terminal. No admin rights were
required (per-user install, no UAC).

Configuration is stored under `%APPDATA%\roomler\roomler\` once you run
the enroll step below.

First-time setup
----------------
Open PowerShell (no need to run as administrator) and run:

    $agent = "$env:LOCALAPPDATA\Programs\Roomler\roomlerd.exe"

    # 1. Generate an enrollment JWT in the admin UI at
    #    http://roomler.ai/ (Admin -> Agents -> New agent).
    #    It is valid for 10 minutes and can only be used once.
    #
    # 2. Enroll this machine:
    & $agent enroll `
        --server http://roomler.ai/ `
        --token <paste-enrollment-jwt> `
        --name $env:COMPUTERNAME

    # 3. Run the agent (foreground — confirm capture + signalling work):
    $env:RUST_LOG = "roomlerd=debug,webrtc=info"
    & $agent run

You should see log lines like:
    agent starting
    signalling connected
    awaiting session

At that point this machine appears (online) in the admin UI at
http://roomler.ai/ under Admin -> Agents. A controller can click
"Connect" to open a remote desktop session.

Autostart on logon (registered automatically since 0.1.54)
----------------------------------------------------------
The MSI registers the auto-start hook automatically on install + on
every upgrade. After running the MSI you should already have a
Scheduled Task called `Roomler` with the resilience XML
(restart-on-failure, battery-defeat, single-instance belt). Confirm
with:

    schtasks /Query /TN Roomler

If you ever need to manage the hook manually (e.g. after restoring a
backup or recovering from the rare Win11 ACL-locked-task scenario):

    & $agent service install     # register / re-register
    & $agent service uninstall   # tear down
    & $agent service status      # query state

Earlier versions (0.1.49 and below) used a simpler `schtasks /Create
/SC ONLOGON` registration without the resilience settings — those
upgrade automatically once the new MSI lands. If your existing task
has an ACL tightened so even the owner can't overwrite it (rare
Win11 quirk), the MSI's RegisterAutostart custom action will silently
skip (Return="ignore" so install completes), and the operator can
delete the locked task from an elevated PowerShell once with:

    schtasks /Delete /TN Roomler /F

then re-run `service install` from a normal shell.

Auto-update
-----------
On every start and every 6 hours, the agent checks GitHub Releases
for a newer version. If one is available, it downloads the MSI and
spawns `msiexec` to install it, then exits so the installer can
overwrite the binary. The Scheduled Task registered by
`service install` relaunches the new version on the next login.

Disable for air-gapped deployments with:

    setx ROOMLERD_AUTO_UPDATE 0

Manual check without installing:

    & $agent self-update --check-only

Optional: Windows Service mode (since 0.1.58)
---------------------------------------------
For fleet / unattended deployments where the host needs to be reachable
*before* anyone logs in (e.g. driving the lock screen for remote
login), the agent ships an opt-in alternative to the per-user
Scheduled Task: it can register itself with the Service Control
Manager as `Roomler`, running under LocalSystem with
AutoStart at boot.

Two ways to get there:

  Option A: download the **per-Machine MSI** (since 0.2.x). The
  release page on GitHub publishes two MSIs side-by-side:
      roomler-agent-<version>-x86_64-pc-windows-msvc.msi
      roomler-agent-<version>-perMachine-x86_64-pc-windows-msvc.msi
  The per-Machine MSI installs files under %ProgramFiles%
  \Roomler and auto-registers the SCM service via a deferred
  custom action. UAC fires once during install. Single
  msiexec invocation, no elevated-PS follow-up. Recommended for
  managed-fleet deployments via group policy / Intune.

  The two MSI flavours are mutually exclusive: each refuses to
  install if the other is already present. Uninstall one before
  switching. The per-User MSI never auto-registers the SCM service
  because perUser installs run in a filtered token that lacks
  CreateService rights.

  Option B: install the **per-User MSI** (this one), then manually
  promote to service mode. Open an elevated PowerShell ("Terminal
  (Admin)"):

    & "$env:LOCALAPPDATA\Programs\Roomler\roomlerd.exe" `
        service install --as-service

The SCM service supervises a per-session worker via WTSQueryUserToken
+ CreateProcessAsUserW: when a user logs in, the service spawns
`roomlerd run` in their session; on logoff / fast-user-switch
the worker is replaced; on Stop the worker is terminated.

Service-mode and Scheduled-Task-mode are independent — installing the
service does not remove the Scheduled Task. To avoid both auto-launching
the same agent, uninstall the Scheduled Task first:

    & $agent service uninstall                # remove Scheduled Task
    & $agent service install --as-service     # register SCM service

Inspect / manage:

    & $agent service status --as-service      # NotInstalled / Stopped / Running
    Get-Service Roomler           # PowerShell native
    sc.exe stop Roomler           # explicit stop

Pre-logon SYSTEM-context capture (the agent itself running capture +
input under SYSTEM when no user is logged in) is planned for a future
release; today, service mode idles until the first user login.

Note on privileges
------------------
The agent intentionally runs un-elevated:

 * Windows UIPI blocks input injection into elevated windows from a
   non-elevated process. That is by design — a connected controller
   cannot take over a UAC prompt on this machine.
 * DXGI screen capture requires an interactive user session (it cannot
   run as a Windows service in session 0).

If you want the controller to interact with an elevated window, restart
that window un-elevated, or use the Windows Security Attention Sequence
(Ctrl+Alt+Delete) on the local keyboard yourself.

Uninstall
---------
Settings -> Apps -> Installed apps -> Roomler Agent -> Uninstall.

NOTE (per-User MSI): the Add/Remove record lives ONLY in the HKCU hive
of the account that ran the install. If the install ran from an
elevated shell using a DIFFERENT admin account (over-the-shoulder UAC),
your Settings > Apps will not show it — look under that admin account,
or use one of the account-independent routes below.

From PowerShell (either finds the product code for you):

    # one-shot, removes every Roomler install this account can see:
    & ([scriptblock]::Create((irm https://roomler.ai/api/setup/install.ps1))) -Uninstall

    # or manually:
    Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall,
                  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall |
        Get-ItemProperty | Where-Object DisplayName -like 'Roomler Agent*' |
        Select-Object DisplayName, DisplayVersion, PSChildName
    msiexec /x {product-code-from-PSChildName}

Logs
----
The agent writes to stderr. To capture a log file for troubleshooting:

    & $agent run 2>&1 | Tee-Object -FilePath "$env:TEMP\roomlerd.log"

Set `RUST_LOG=roomlerd=debug,webrtc=debug` for verbose output.

Support
-------
Project:  https://roomler.ai/
Source:   https://github.com/gjovanov/roomler-ai
# RETIRED-NAME-ANCHOR-END
