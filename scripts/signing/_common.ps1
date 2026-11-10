# Shared helpers for the scripts/signing/* operator scripts.
#
# Dot-source this from every numbered script:  . "$PSScriptRoot\_common.ps1"
#
# ASCII-only, same rule as scripts/install.ps1: these files may be pasted
# into a Windows PowerShell 5.1 host that reads BOM-less files as ANSI,
# where multibyte UTF-8 punctuation decodes into smart quotes and BREAKS
# the parser. No em-dashes, no curly quotes, no arrows.

$ErrorActionPreference = 'Stop'

# State shared across the numbered scripts so the operator types each
# value once. Deliberately NOT secret: account names, GUIDs and a
# tenant id are all public-ish identifiers. Gitignored anyway.
$script:StatePath = Join-Path $PSScriptRoot '.meshharbor-signing.json'

function Say  ([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok   ([string]$msg) { Write-Host "    OK  $msg" -ForegroundColor Green }
function Warn ([string]$msg) { Write-Host "    WARNING: $msg" -ForegroundColor Yellow }
function Info ([string]$msg) { Write-Host "    $msg" }
function Fail ([string]$msg) { Write-Host "    ERROR: $msg" -ForegroundColor Red; exit 1 }

function Read-State {
    if (Test-Path $script:StatePath) {
        return (Get-Content $script:StatePath -Raw | ConvertFrom-Json)
    }
    return [pscustomobject]@{}
}

function Save-State($state) {
    $state | ConvertTo-Json -Depth 6 | Set-Content -Path $script:StatePath -Encoding ascii
    Ok "state saved -> $($script:StatePath)"
}

function Set-StateValue($state, [string]$key, $value) {
    if ($state.PSObject.Properties.Name -contains $key) { $state.$key = $value }
    else { $state | Add-Member -NotePropertyName $key -NotePropertyValue $value }
    return $state
}

function Get-StateValue($state, [string]$key, $fallback = $null) {
    if ($state.PSObject.Properties.Name -contains $key -and $state.$key) { return $state.$key }
    return $fallback
}

function Require-Command([string]$name, [string]$hint) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $cmd) { Fail "'$name' not found on PATH. $hint" }
    return $cmd
}

# az emits JSON on stdout and diagnostics on stderr; $ErrorActionPreference
# = 'Stop' turns any stderr write into a terminating error under some hosts,
# so route every az call through here.
function Invoke-Az {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & az @Args 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
    if ($code -ne 0) {
        Write-Host ($out | Out-String) -ForegroundColor Red
        Fail "az $($Args -join ' ') failed with exit code $code"
    }
    return ($out | Out-String)
}

function Invoke-AzJson {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $text = Invoke-Az @Args
    if (-not $text.Trim()) { return $null }
    # Invoke-Az merges stderr, and az writes preview/experimental WARNINGs
    # there (e.g. "WARNING: Command group 'az artifact-signing' is in
    # preview..."), which land BEFORE the JSON and break ConvertFrom-Json.
    # Parse from the first '{' or '[' instead of trusting the whole stream.
    $idx = $text.IndexOfAny([char[]]@('{', '['))
    if ($idx -lt 0) { return $null }
    return ($text.Substring($idx) | ConvertFrom-Json)
}

# Azure regions that host Artifact Signing, and the signing endpoint each
# one exposes. The endpoint is what the CI action needs -- it is NOT
# derivable from the region name, so it is table-driven.
$script:SigningRegions = [ordered]@{
    'brazilsouth'    = 'https://brs.codesigning.azure.net'
    'centralus'      = 'https://cus.codesigning.azure.net'
    'eastus'         = 'https://eus.codesigning.azure.net'
    'japaneast'      = 'https://jpe.codesigning.azure.net'
    'koreacentral'   = 'https://krc.codesigning.azure.net'
    'northcentralus' = 'https://ncus.codesigning.azure.net'
    'northeurope'    = 'https://neu.codesigning.azure.net'
    'polandcentral'  = 'https://plc.codesigning.azure.net'
    'southcentralus' = 'https://scus.codesigning.azure.net'
    'switzerlandnorth' = 'https://swn.codesigning.azure.net'
    'westcentralus'  = 'https://wcus.codesigning.azure.net'
    'westeurope'     = 'https://weu.codesigning.azure.net'
    'westus'         = 'https://wus.codesigning.azure.net'
    'westus2'        = 'https://wus2.codesigning.azure.net'
    'westus3'        = 'https://wus3.codesigning.azure.net'
}

function Get-SigningEndpoint([string]$Location) {
    $key = $Location.ToLower().Replace(' ', '')
    if (-not $script:SigningRegions.Contains($key)) {
        Fail ("region '$Location' does not host Artifact Signing. Supported: " +
              ($script:SigningRegions.Keys -join ', '))
    }
    return $script:SigningRegions[$key]
}

# Countries where Artifact Signing issues PUBLIC TRUST certificates to an
# ORGANIZATION. (Individual developers are restricted to US/CA -- which is
# why meshharbor signs under a company identity.) EU members are listed
# individually so the preflight can give a definite yes/no.
$script:PublicTrustOrgCountries = @(
    # EU
    'AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE',
    'IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE',
    # Non-EU
    'US','CA','GB','AU','NZ','JP','KR','SG','CH','NO','IL'
)

function Test-PublicTrustCountry([string]$TwoLetter) {
    return $script:PublicTrustOrgCountries -contains $TwoLetter.ToUpper()
}

$script:DefaultRepo = 'jk-zhang-meta/MeshHarbor'
