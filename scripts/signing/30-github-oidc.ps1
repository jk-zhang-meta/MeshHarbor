# 30-github-oidc.ps1 -- wire GitHub Actions to the certificate profile with
# OpenID Connect, so CI can sign WITHOUT any key material or client secret
# stored in the repository.
#
#   pwsh scripts/signing/30-github-oidc.ps1
#   pwsh scripts/signing/30-github-oidc.ps1 -AppName meshharbor-signing -WhatIfOnly
#
# Creates:
#   1. an Entra app registration + service principal (no secret, ever)
#   2. federated identity credentials trusting this repo's Actions OIDC token
#   3. the 'Artifact Signing Certificate Profile Signer' role assignment,
#      scoped to the CERTIFICATE PROFILE (not the account, not the RG)
#   4. six repository VARIABLES (not secrets -- none of them are confidential)
#
# Least privilege worth noting: the service principal can sign with one
# profile and read signing history. It cannot create profiles, cannot
# manage identity validations, and cannot read anything else in the
# subscription.

[CmdletBinding()]
param(
    [string]$AppName = 'meshharbor-github-signing',
    [string]$Repo    = '',
    # Branch allowed to sign on workflow_dispatch rehearsals.
    [string]$Branch  = 'master',
    # Fallback trust anchor when the tenant lacks wildcard (flexible) FICs.
    [string]$Environment = 'release',
    [switch]$WhatIfOnly
)

. "$PSScriptRoot\_common.ps1"

$state = Read-State
$subscriptionId = Get-StateValue $state 'subscriptionId'
$tenantId       = Get-StateValue $state 'tenantId'
$profileId      = Get-StateValue $state 'profileResourceId'
$endpoint       = Get-StateValue $state 'endpoint'
$accountName    = Get-StateValue $state 'accountName'
$profileName    = Get-StateValue $state 'profileName'
if (-not $Repo) { $Repo = Get-StateValue $state 'repo' $script:DefaultRepo }

if (-not $profileId) { Fail 'no certificate profile recorded. Run 20-azure-cert-profile.ps1 first.' }

Invoke-Az account set --subscription $subscriptionId | Out-Null

# ------------------------------------------------------------ app + sp
Say "Entra app registration '$AppName'"
$apps = Invoke-AzJson ad app list --display-name $AppName
if ($apps -and $apps.Count -gt 0) {
    $app = $apps[0]
    Ok "already exists (appId $($app.appId))"
} elseif ($WhatIfOnly) {
    Info '  would create the app registration'
    $app = [pscustomobject]@{ appId = '<pending>'; id = '<pending>' }
} else {
    $app = Invoke-AzJson ad app create --display-name $AppName --sign-in-audience AzureADMyOrg
    Ok "created (appId $($app.appId))"
}
$appId = $app.appId

if (-not $WhatIfOnly) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $spRaw = & az ad sp show --id $appId -o json 2>$null
    $spCode = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($spCode -eq 0 -and $spRaw) {
        $sp = $spRaw | ConvertFrom-Json
        Ok "service principal exists ($($sp.id))"
    } else {
        $sp = Invoke-AzJson ad sp create --id $appId
        Ok "service principal created ($($sp.id))"
    }
}

# ------------------------------------------- federated identity credentials
#
# Entra's plain `subject` is an EXACT string match -- 'refs/tags/*' as a
# literal subject silently never matches. Two workable shapes:
#
#   (a) flexible FIC (claimsMatchingExpression) -- real wildcard support
#   (b) an exact subject bound to a GitHub Environment
#
# Prefer (a); fall back to (b) and say so, because (b) additionally
# requires `environment:` on the signing jobs.
Say 'Federated identity credentials'

$issuer   = 'https://token.actions.githubusercontent.com'
$audience = 'api://AzureADTokenExchange'

function Get-ExistingFic([string]$name) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $raw = & az ad app federated-credential list --id $appId -o json 2>$null
    $ErrorActionPreference = $prev
    if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
    return ($raw | ConvertFrom-Json) | Where-Object { $_.name -eq $name }
}

function New-Fic([string]$name, [hashtable]$body) {
    if (Get-ExistingFic $name) { Ok "$name already exists"; return $true }
    if ($WhatIfOnly) { Info "  would create FIC $name"; return $true }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "fic-$name.json"
    ($body | ConvertTo-Json -Depth 5) | Set-Content -Path $tmp -Encoding ascii
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $out = & az ad app federated-credential create --id $appId --parameters "@$tmp" 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    if ($code -ne 0) {
        Warn "could not create FIC ${name}:"
        Write-Host ($out | Out-String) -ForegroundColor DarkGray
        return $false
    }
    Ok "$name created"
    return $true
}

# (1) Exact subject for the rehearsal branch. Always supported.
New-Fic 'github-branch' @{
    name      = 'github-branch'
    issuer    = $issuer
    subject   = "repo:${Repo}:ref:refs/heads/$Branch"
    audiences = @($audience)
    description = "meshharbor workflow_dispatch rehearsals from $Branch"
} | Out-Null

# (2) Wildcard over all three release tag families.
$tagsOk = New-Fic 'github-release-tags' @{
    name      = 'github-release-tags'
    issuer    = $issuer
    audiences = @($audience)
    description = 'meshharbor agent-v* / setup-v* / tunnel-v* release tags'
    claimsMatchingExpression = @{
        value = "claims['sub'] matches 'repo:${Repo}:ref:refs/tags/*'"
        languageVersion = 1
    }
}

$useEnvironment = $false
if (-not $tagsOk) {
    Warn 'wildcard (flexible) federated credentials are unavailable in this tenant.'
    Info "  Falling back to a GitHub Environment-bound credential ('$Environment')."
    $useEnvironment = $true
    New-Fic 'github-environment' @{
        name      = 'github-environment'
        issuer    = $issuer
        subject   = "repo:${Repo}:environment:$Environment"
        audiences = @($audience)
        description = "meshharbor releases via the '$Environment' environment"
    } | Out-Null
}

# ------------------------------------------------------------------ role
Say "Role assignment (scoped to the certificate profile)"
Info "  scope: $profileId"
if ($WhatIfOnly) {
    Info '  would assign: Artifact Signing Certificate Profile Signer'
} else {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $have = & az role assignment list --assignee $appId --scope $profileId -o json 2>$null
    $ErrorActionPreference = $prev
    $already = $false
    if ($LASTEXITCODE -eq 0 -and $have) {
        $already = (($have | ConvertFrom-Json) |
                    Where-Object { $_.roleDefinitionName -eq 'Artifact Signing Certificate Profile Signer' }).Count -gt 0
    }
    if ($already) {
        Ok 'Artifact Signing Certificate Profile Signer already assigned'
    } else {
        # Entra replication lag: a brand-new SP is not immediately visible
        # to ARM's role-assignment validator. Retry rather than fail.
        $assigned = $false
        for ($i = 1; $i -le 10; $i++) {
            $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
            $out = & az role assignment create --assignee $appId `
                     --role 'Artifact Signing Certificate Profile Signer' `
                     --scope $profileId 2>&1
            $code = $LASTEXITCODE
            $ErrorActionPreference = $prev
            if ($code -eq 0) { $assigned = $true; break }
            Info "  attempt $i/10 failed (Entra replication lag is normal here); retrying in 10 s"
            Start-Sleep -Seconds 10
        }
        if (-not $assigned) { Fail 'could not assign the signer role. See the output above.' }
        Ok 'Artifact Signing Certificate Profile Signer assigned'
    }
}

# ------------------------------------------------------- repo variables
Say "Repository variables on $Repo"
$vars = [ordered]@{
    AZURE_SIGNING_ENDPOINT = $endpoint
    AZURE_SIGNING_ACCOUNT  = $accountName
    AZURE_SIGNING_PROFILE  = $profileName
    AZURE_CLIENT_ID        = $appId
    AZURE_TENANT_ID        = $tenantId
    AZURE_SUBSCRIPTION_ID  = $subscriptionId
}
$subject = Get-StateValue $state 'certificateSubject' ''
if ($subject) {
    # Locks the publisher: the action fails if a signature's subject stops
    # containing this, so swapping the profile can never silently change
    # who Windows reports as the verified publisher.
    $cn = $subject
    if ($subject -match 'CN=([^,]+)') { $cn = $Matches[1].Trim() }
    $vars['AZURE_SIGNING_EXPECT_SUBJECT'] = $cn
}

foreach ($k in $vars.Keys) {
    $v = $vars[$k]
    if (-not $v) { Warn "$k has no value in state -- skipping"; continue }
    if ($WhatIfOnly) { Info "  would set $k = $v"; continue }
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & gh variable set $k --repo $Repo --body "$v" 2>&1 | Out-Null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($code -ne 0) { Warn "failed to set $k" } else { Ok "$k = $v" }
}

$state = Set-StateValue $state 'appId' $appId
$state = Set-StateValue $state 'usesEnvironmentFic' $useEnvironment
Save-State $state

Write-Host ''
if ($useEnvironment) {
    Warn "This tenant needed the Environment fallback. Before tagging a release:"
    Info "  1. Create the '$Environment' environment on $Repo"
    Info '  2. CI is retired. Do not create signing jobs; see docs/local-build.md.'
}
Ok 'OIDC wiring complete. No signing key material exists in GitHub.'
Info ''
Info 'Verify end to end without a tag:'
Info '  CI is retired; follow docs/local-build.md for explicit local preparation.'
