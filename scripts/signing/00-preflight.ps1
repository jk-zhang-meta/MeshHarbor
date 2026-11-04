# 00-preflight.ps1 -- verify everything needed BEFORE spending money or
# starting the (1 to 20 business day) Azure identity-validation clock.
#
# Checks tooling, Azure login, subscription, region eligibility, the
# billing-account type (an INDIVIDUAL billing account cannot validate an
# ORGANIZATION identity -- and meshharbor must sign as an organization,
# because Azure Artifact Signing only issues individual Public Trust
# certificates to US/Canada residents), and GitHub CLI auth.
#
# Nothing here mutates anything. Safe to run repeatedly.
#
#   pwsh scripts/signing/00-preflight.ps1 -Country AT
#   pwsh scripts/signing/00-preflight.ps1 -SubscriptionId <guid> -Location westeurope
#
# On success it writes scripts/signing/.meshharbor-signing.json, which every
# later script in this directory reads so values are typed exactly once.

[CmdletBinding()]
param(
    [string]$SubscriptionId = '',
    [string]$Location       = 'westeurope',
    [string]$ResourceGroup  = 'rg-meshharbor-signing',
    [string]$AccountName    = 'meshharborsigning',
    [string]$ProfileName    = 'meshharbor-public-trust',
    # ISO 3166-1 alpha-2 of the country the company is registered in.
    # G ROX LTD is registered in Bulgaria -- an EU member, so it qualifies for
    # ORGANIZATION Public Trust certificates. (Individual Public Trust is
    # US/Canada only, which is why signing goes through the company.)
    [string]$Country        = 'BG',
    [string]$Repo           = ''
)

. "$PSScriptRoot\_common.ps1"

$state = Read-State
if (-not $Repo) { $Repo = Get-StateValue $state 'repo' $script:DefaultRepo }

$problems = @()

# ---------------------------------------------------------------- tooling
Say 'Tooling'

Require-Command 'az' 'Install: https://aka.ms/installazurecli' | Out-Null
$azVer = (Invoke-AzJson version).'azure-cli'
Ok "azure-cli $azVer"

Require-Command 'gh' 'Install: https://cli.github.com/' | Out-Null
$ghVer = (& gh --version 2>&1 | Select-Object -First 1)
Ok "$ghVer"

if ($PSVersionTable.PSVersion.Major -lt 5) {
    $problems += 'PowerShell 5.1 or newer is required.'
} else {
    Ok "PowerShell $($PSVersionTable.PSVersion)"
}

# The artifact-signing extension is what 10/20 use. Report but do not
# install -- 10-azure-provision.ps1 installs it as part of its own run.
$ext = Invoke-AzJson extension list
if ($ext | Where-Object { $_.name -eq 'artifact-signing' }) {
    Ok 'az extension "artifact-signing" installed'
} else {
    Info 'az extension "artifact-signing" not installed yet (10-azure-provision.ps1 installs it)'
}

# ------------------------------------------------------------------ azure
Say 'Azure account'

$account = Invoke-AzJson account show
if (-not $account) { Fail 'not logged in. Run: az login' }
Ok "signed in as $($account.user.name) (tenant $($account.tenantId))"

if (-not $SubscriptionId) {
    $SubscriptionId = Get-StateValue $state 'subscriptionId' $account.id
}
$subs = Invoke-AzJson account list --all
$sub  = $subs | Where-Object { $_.id -eq $SubscriptionId }
if (-not $sub) {
    Warn "subscription '$SubscriptionId' not visible to this login. Available:"
    foreach ($s in $subs) { Info "  $($s.id)  $($s.name)" }
    $problems += "subscription '$SubscriptionId' not found -- pass -SubscriptionId <guid>."
} else {
    Ok "subscription $($sub.name) [$($sub.id)] state=$($sub.state)"
    if ($sub.state -ne 'Enabled') { $problems += "subscription state is $($sub.state), expected Enabled." }
}

# ----------------------------------------------------------------- region
Say 'Region'
$endpoint = Get-SigningEndpoint $Location
Ok "$Location -> $endpoint"

# -------------------------------------------------------- billing account
# The org-vs-individual distinction is the single most common way this
# onboarding fails: identity-validation type MUST match the billing
# account type, and the mismatch is only discovered after the portal form
# is submitted. Check it up front. Requires billing-reader rights; a
# failure here is a warning, not a hard stop.
Say 'Billing account (identity validation type must match)'
$billingOk = $false
try {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $billingRaw = & az billing account list -o json 2>$null
    $ErrorActionPreference = $prev
    if ($LASTEXITCODE -eq 0 -and $billingRaw) {
        foreach ($b in ($billingRaw | ConvertFrom-Json)) {
            $type = $b.agreementType
            $name = $b.displayName
            $kind = $b.accountType
            Info "  $name  agreement=$type accountType=$kind"
            if ($kind -eq 'Organization' -or $kind -eq 'Enterprise') { $billingOk = $true }
        }
    }
} catch {
    $ErrorActionPreference = 'Stop'
}
if ($billingOk) {
    Ok 'an Organization billing account is present'
} else {
    Warn 'could not confirm an Organization billing account from the CLI.'
    Info 'Verify by hand in the portal: Cost Management + Billing -> Billing scopes ->'
    Info 'the account must show Account Type = Organization, and its LEGAL NAME and'
    Info 'ADDRESS must already match, character for character, what you want on the'
    Info 'certificate. Individual identity validation sources these fields straight'
    Info 'from the billing profile and they are read-only in the validation form.'
}

# ---------------------------------------------------------------- country
Say 'Public Trust country eligibility (organization identity)'
if (-not $Country) {
    Warn 'no -Country given; skipping the eligibility check.'
    Info 'Pass the ISO 3166-1 alpha-2 code of the country the company is registered in, e.g. -Country AT'
} elseif (Test-PublicTrustCountry $Country) {
    Ok "$($Country.ToUpper()) is eligible for organization Public Trust certificates"
} else {
    $problems += ("country '$($Country.ToUpper())' is not on the Artifact Signing Public Trust list. " +
                  'Organizations are supported in the EU, US, CA, GB, AU, NZ, JP, KR, SG, CH, NO and IL.')
}

# --------------------------------------------------------------- github
Say 'GitHub'
$prev = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& gh auth status 2>&1 | Out-Null
$ghCode = $LASTEXITCODE
$ErrorActionPreference = $prev
if ($ghCode -ne 0) {
    $problems += 'gh is not authenticated. Run: gh auth login'
} else {
    Ok 'gh authenticated'
}

$prev = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$repoJson = & gh repo view $Repo --json viewerPermission 2>$null
$ErrorActionPreference = $prev
if ($LASTEXITCODE -eq 0 -and $repoJson) {
    $perm = ($repoJson | ConvertFrom-Json).viewerPermission
    if ($perm -in @('ADMIN', 'MAINTAIN')) { Ok "$Repo permission=$perm (can set variables + secrets)" }
    else { $problems += "insufficient permission on ${Repo}: $perm (need ADMIN or MAINTAIN to set repo variables)." }
} else {
    $problems += "cannot read $Repo with gh."
}

# ------------------------------------------------------------- checklist
Say 'Have these ready for the portal identity-validation form (step 10)'
Info '  * Legal entity name EXACTLY as it appears in the business register'
Info '  * Business/registry identifier (e.g. Firmenbuchnummer, HRB, Companies House no.)'
Info '  * Registered address: street, city, state/province, postal code, country'
Info '  * Website on the company domain: https://meshharbor.itachi.fans'
Info '  * Primary AND secondary monitored email, BOTH on a domain the entity owns'
Info '    (they must accept external links; verification links expire in 7 days)'
Info '  * A government photo ID for the individual representing the organization'
Info '  * Public business-register record up to date (stale records slow validation)'

# ----------------------------------------------------------------- result
Write-Host ''
if ($problems.Count -gt 0) {
    Write-Host 'PREFLIGHT FAILED' -ForegroundColor Red
    foreach ($p in $problems) { Write-Host "  - $p" -ForegroundColor Red }
    exit 1
}

$state = Set-StateValue $state 'subscriptionId' $SubscriptionId
$state = Set-StateValue $state 'tenantId'       $account.tenantId
$state = Set-StateValue $state 'location'       $Location.ToLower()
$state = Set-StateValue $state 'endpoint'       $endpoint
$state = Set-StateValue $state 'resourceGroup'  $ResourceGroup
$state = Set-StateValue $state 'accountName'    $AccountName
$state = Set-StateValue $state 'profileName'    $ProfileName
$state = Set-StateValue $state 'repo'           $Repo
if ($Country) { $state = Set-StateValue $state 'country' $Country.ToUpper() }
Save-State $state

Write-Host 'PREFLIGHT OK' -ForegroundColor Green
Info 'Next: pwsh scripts/signing/10-azure-provision.ps1'
