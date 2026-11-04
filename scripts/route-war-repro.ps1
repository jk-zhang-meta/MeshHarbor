<#
.SYNOPSIS
  Reproduce the overlay route-reassertion war (#1328 "Mode A") on demand, so
  the stand-down can be field-verified without waiting for a corp VPN to do it.

.DESCRIPTION
  The guard's stand-down engages on STRIKES, and a strike is "a route we wrote
  is gone again when we look". Only a competitor deleting OUR routes produces
  that. This deletes them, on a timer, exactly as a VPN route monitor does --
  so the daemon cannot tell the difference and the real code path runs.

  It is deliberately NOT a switch inside the daemon. A fault injector whose
  job is to make overlay routes disappear, shipped to a fleet that runs as
  SYSTEM, is one mis-set variable away from taking an operator's remote access
  to their own box -- the exact outcome the overlay's "never self-wedge"
  commitment exists to prevent. An external reaper has the same fidelity and
  none of that blast radius: kill it and the next guard wave heals the host.

.PARAMETER Seconds
  How long to reap. REQUIRED, and capped -- there is no unbounded mode.

.PARAMETER IntervalMs
  Delay between sweeps. Default 700ms: comfortably faster than the guard's
  ~2s wave, so every wave finds its route missing and takes a strike.

.PARAMETER Adapter
  The overlay adapter to reap. Default 'meshharbor'.

.PARAMETER Family
  IPv4 (peer /32s -- the #1328 Mode A shape) or IPv6 (the ULA). Default IPv4.

.EXAMPLE
  # From another mesh node, on a host running the build under test:
  meshharbor exec <device> "& 'C:\Program Files\MeshHarbor\scripts\route-war-repro.ps1' -Seconds 180"

.NOTES
  Read the result as a DIFF of two `meshharbor status` readings, never an
  absolute (the counters are cumulative). The pass signature for #1328 is
  `evicted` flattening while `yielded` climbs. A `yielded` that stays 0 means
  the stand-down never engaged and the run measured nothing -- that is a
  FAILED test, not a quiet one.

  Safety: only ever deletes routes ON THE OVERLAY ADAPTER. It never touches
  another product's rows, so it cannot be mistaken for -- or turn into -- the
  eviction half of the war.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(10, 900)]
    [int]$Seconds,

    [ValidateRange(100, 5000)]
    [int]$IntervalMs = 700,

    [string]$Adapter = 'meshharbor',

    [ValidateSet('IPv4', 'IPv6')]
    [string]$Family = 'IPv4'
)

$ErrorActionPreference = 'Stop'

$if = Get-NetAdapter -Name $Adapter -ErrorAction SilentlyContinue
if (-not $if) {
    Write-Error "no adapter named '$Adapter' -- is the daemon running with an overlay?"
    exit 1
}
Write-Host "adapter : $($if.Name) (ifIndex $($if.ifIndex))"
Write-Host "family  : $Family"
Write-Host "reaping : every ${IntervalMs}ms for ${Seconds}s"
Write-Host ''
Write-Host 'Take a `meshharbor status` reading NOW and another when this exits;'
Write-Host 'the verdict is the DIFF: evicted flat + yielded climbing = pass.'
Write-Host ''

# The prefixes the guard defends and will therefore re-assert. Restricting the
# match to this adapter is what keeps the reaper honest: we simulate a
# competitor deleting OUR rows, never the reverse.
function Get-Targets {
    Get-NetRoute -AddressFamily $Family -ErrorAction SilentlyContinue |
        Where-Object { $_.ifIndex -eq $if.ifIndex } |
        Where-Object {
            if ($Family -eq 'IPv4') {
                # Peer /32s and the carved block/connected prefixes.
                $_.DestinationPrefix -match '^100\.6[4-9]\.' -or
                $_.DestinationPrefix -match '^100\.(7[0-9]|1[01][0-9]|12[0-7])\.'
            } else {
                $_.DestinationPrefix -like 'fd72:6f6f:6d6c:*'
            }
        }
}

$deadline = (Get-Date).AddSeconds($Seconds)
$deleted = 0
$sweeps = 0

try {
    while ((Get-Date) -lt $deadline) {
        $sweeps++
        foreach ($r in Get-Targets) {
            try {
                Remove-NetRoute -InputObject $r -Confirm:$false -ErrorAction Stop
                $deleted++
            } catch {
                # Already gone, or the guard re-added it between enumerate and
                # delete. Both are the race we are deliberately creating.
            }
        }
        Start-Sleep -Milliseconds $IntervalMs
    }
} finally {
    Write-Host ''
    Write-Host "sweeps  : $sweeps"
    Write-Host "deleted : $deleted route(s)"
    Write-Host ''
    # Leaving the host wedged would be an unacceptable way for a test to end,
    # so say plainly what heals it. The guard re-asserts within ~2s of the
    # last sweep; this only reports, it does not need to repair.
    Write-Host 'Reaping stopped. The route guard re-asserts within ~2s;'
    Write-Host 'confirm with `meshharbor peers` before walking away.'
}
