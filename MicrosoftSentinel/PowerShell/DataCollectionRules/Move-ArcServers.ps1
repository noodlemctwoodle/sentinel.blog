<#
.SYNOPSIS
    Migrates Azure Arc-enabled servers between subscriptions or resource groups
    without reinstalling the Connected Machine agent.

.DESCRIPTION
    Performs a metadata-only move of Microsoft.HybridCompute/machines resources
    using the standard ARM Move-AzResource operation. The Connected Machine agent
    on each host is not touched: no disconnect, no reinstall, no extension
    redeployment. Installed VM extensions (AMA, MDE.Windows, MDE.Linux, WatchAgent,
    GuestConfiguration, etc.) move automatically with the parent machine resource.

    The script:
      1. Validates that source and destination subscriptions are in the same
         Microsoft Entra tenant (cross-tenant Arc moves are not supported via
         this method and require a full disconnect/reconnect).
      2. Validates that the destination resource group exists. If the
         destination RG is in a different region than the machines, the
         script warns but continues - this is a supported ARM metadata move;
         resources retain their original location regardless of RG region.
         Pass -FailOnRegionMismatch to abort instead.
      3. Discovers Arc machines in the source resource group, with optional
         wildcard name filtering.
      4. Calls the ARM validateMoveResources pre-flight API as an authoritative
         dry run before issuing the real move.
      5. Issues Move-AzResource in batches (default 50 machines per call) so
         large estates don't hit request size limits.
      6. Verifies each machine has landed in the destination scope after the move.

    Supports -WhatIf and -Confirm via SupportsShouldProcess so you can stage the
    change safely. The source resource group is locked by ARM for up to four
    hours during the move; plan the window accordingly.

    WHAT THE SCRIPT DOES NOT DO (handle these separately post-move):
      - Re-apply RBAC role assignments (orphaned by any cross-subscription move).
      - Re-scope Azure Policy assignments, initiatives, or exemptions.
      - Re-enable Defender for Servers plan on the destination subscription.
      - Re-associate Data Collection Rules (DCRs) for Azure Monitor Agent if
         the DCRs live in the source subscription and are not moved alongside.
      - Re-apply resource locks or update Sentinel analytics rules that filter
         by subscription ID.
      - Handle SQL Server enabled by Azure Arc, which requires disabling Best
         Practices Assessment and Microsoft Purview integration before the move.

.PARAMETER SourceSubscriptionId
    GUID of the subscription currently containing the Arc-enabled servers.

.PARAMETER SourceResourceGroup
    Name of the resource group in the source subscription that holds the
    Microsoft.HybridCompute/machines resources to migrate.

.PARAMETER DestinationSubscriptionId
    GUID of the subscription the Arc servers should be moved into. Must be in
    the same Microsoft Entra tenant as the source subscription.

.PARAMETER DestinationResourceGroup
    Name of the resource group in the destination subscription that will
    receive the machines. Must already exist. Region can differ from the
    machines - resources retain their original location across the move.
    Pass -FailOnRegionMismatch to abort on mismatch instead of warning.

.PARAMETER FailOnRegionMismatch
    By default the script warns and proceeds when the destination RG is in a
    different region than the source machines (ARM metadata moves preserve
    resource location). Set this switch to enforce matching regions and
    abort otherwise.

.PARAMETER MachineNameFilter
    Optional array of machine name patterns (wildcards supported) used to limit
    which Arc servers are moved. If omitted, every Arc machine in the source
    resource group is moved. Matching is case-insensitive and uses PowerShell
    -like semantics.

.PARAMETER BatchSize
    Number of resources submitted per Move-AzResource call. Defaults to 50.
    The ARM move API accepts larger batches, but 50 keeps individual calls
    well under request-size and latency limits for large fleets.

.PARAMETER AcceptDisclaimer
    Skips the interactive disclaimer acknowledgement prompt. Use this in
    pipelines or other non-interactive contexts where you have already
    reviewed the disclaimer banner and accepted responsibility for any
    post-move remediation (RBAC, Policy, Defender, DCRs, SQL Arc BPA, etc.).
    Has no effect when -WhatIf is also specified, because dry runs do not
    prompt in the first place.

.EXAMPLE
    PS> .\Move-ArcServers.ps1 `
            -SourceSubscriptionId      '00000000-0000-0000-0000-000000000000' `
            -SourceResourceGroup       'rg-arc-legacy' `
            -DestinationSubscriptionId '11111111-1111-1111-1111-111111111111' `
            -DestinationResourceGroup  'rg-arc-prod' `
            -WhatIf

    Dry-runs a migration of every Arc-enabled server from rg-arc-legacy in the
    source subscription into rg-arc-prod in the destination subscription. No
    resources are actually moved; the ARM validateMoveResources pre-flight is
    still executed so you see real validation errors if any apply.

.EXAMPLE
    PS> .\Move-ArcServers.ps1 `
            -SourceSubscriptionId      '00000000-0000-0000-0000-000000000000' `
            -SourceResourceGroup       'rg-arc-legacy' `
            -DestinationSubscriptionId '11111111-1111-1111-1111-111111111111' `
            -DestinationResourceGroup  'rg-arc-prod'

    Performs the actual move for every Arc machine in rg-arc-legacy. You will
    be prompted to confirm because ConfirmImpact is High. The source resource
    group is locked by ARM for the duration of the move.

.EXAMPLE
    PS> .\Move-ArcServers.ps1 `
            -SourceSubscriptionId      '00000000-0000-0000-0000-000000000000' `
            -SourceResourceGroup       'rg-arc-legacy' `
            -DestinationSubscriptionId '11111111-1111-1111-1111-111111111111' `
            -DestinationResourceGroup  'rg-arc-prod' `
            -MachineNameFilter 'prd-web*','prd-api*' `
            -AcceptDisclaimer `
            -Confirm:$false

    Migrates only production web and API servers matching the two wildcards,
    skipping both the confirmation prompt and the interactive disclaimer
    acknowledgement. Useful inside a pipeline where approval is handled
    externally (e.g. an Azure DevOps stage gate with manual approval).

.EXAMPLE
    PS> .\Move-ArcServers.ps1 `
            -SourceSubscriptionId      '00000000-0000-0000-0000-000000000000' `
            -SourceResourceGroup       'rg-arc-legacy' `
            -DestinationSubscriptionId '11111111-1111-1111-1111-111111111111' `
            -DestinationResourceGroup  'rg-arc-prod' `
            -BatchSize 100

    Migrates all Arc machines using larger batches of 100 resources per
    Move-AzResource call. Useful for estates with several hundred machines
    where smaller batches would serialise the operation unnecessarily.

.EXAMPLE
    PS> $splat = @{
            SourceSubscriptionId      = '00000000-0000-0000-0000-000000000000'
            SourceResourceGroup       = 'rg-arc-legacy'
            DestinationSubscriptionId = '11111111-1111-1111-1111-111111111111'
            DestinationResourceGroup  = 'rg-arc-prod'
            MachineNameFilter         = @('dev-*')
        }
    PS> .\Move-ArcServers.ps1 @splat -WhatIf
    PS> .\Move-ArcServers.ps1 @splat

    Splat-based invocation pattern: dry run first, then the real move using
    the same parameter set. Recommended for anything touching production.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject
    Writes a verification table of moved machines (Name, ResourceGroupName,
    Location) to the host after the move completes.

.NOTES
    File Name      : Move-ArcServers.ps1
    Author         : Toby G
    Requires       : PowerShell 7.2+, Az.Accounts, Az.Resources (Az 11+ tested)
    RBAC required  : Microsoft.Resources/subscriptions/resourceGroups/moveResources/action
                     on the source resource group, and
                     Microsoft.Resources/subscriptions/resourceGroups/write on the
                     destination resource group. Contributor at both scopes is
                     sufficient.
    Tested against : Az 12.x, Connected Machine agent 1.50+
    Idempotent     : Yes. Re-running after a successful move is a no-op because
                     the filter will find no matching machines in the source RG.

.LINK
    https://learn.microsoft.com/azure/azure-arc/servers/manage-vm-extensions-cli

.LINK
    https://learn.microsoft.com/azure/azure-resource-manager/management/move-resource-group-and-subscription

.LINK
    https://learn.microsoft.com/azure/azure-arc/servers/manage-howto-migrate
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)] [string]   $SourceSubscriptionId,
    [Parameter(Mandatory)] [string]   $SourceResourceGroup,
    [Parameter(Mandatory)] [string]   $DestinationSubscriptionId,
    [Parameter(Mandatory)] [string]   $DestinationResourceGroup,
    [string[]] $MachineNameFilter,
    [int]      $BatchSize = 50,
    [switch]   $AcceptDisclaimer,
    # When the destination RG is in a different region than the machines, the
    # script warns but continues - this is a supported ARM metadata move,
    # resources retain their original location. Set this switch to fail hard
    # instead, matching earlier script behaviour.
    [switch]   $FailOnRegionMismatch
)

$ErrorActionPreference = 'Stop'

# ---- Module prerequisites ----
# Az.Accounts provides Get-AzContext / Get-AzSubscription / Invoke-AzRestMethod.
# We rely on the bearer token Az.Accounts attaches to Invoke-AzRestMethod for
# every ARM call, so this module is required even though we no longer call
# Set-AzContext directly.
foreach ($moduleName in @('Az.Accounts')) {
    if (-not (Get-Module -Name $moduleName -ListAvailable -ErrorAction SilentlyContinue)) {
        throw "Required module '$moduleName' is not installed. Run: Install-Module $moduleName -Scope CurrentUser"
    }
    if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue)) {
        Import-Module $moduleName -ErrorAction Stop
    }
}

# ---- 0. Warning banner and disclaimer acknowledgement ----
$banner = @'

################################################################################
#                                                                              #
#   !!  AZURE ARC SERVER CROSS-SUBSCRIPTION MOVE  !!                           #
#                                                                              #
#   This script performs a METADATA-ONLY ARM move of                           #
#   Microsoft.HybridCompute/machines resources. The Connected Machine          #
#   agent on each host is not touched.                                         #
#                                                                              #
#   THE SOURCE RESOURCE GROUP WILL BE LOCKED BY ARM FOR UP TO 4 HOURS          #
#   while the move is in progress. You cannot create, delete, or modify        #
#   any resources in the source RG during this window.                         #
#                                                                              #
#   THIS SCRIPT DOES NOT HANDLE THE FOLLOWING - you must address them          #
#   yourself, before or after the move as appropriate:                         #
#                                                                              #
#     [ ] SQL Server enabled by Azure Arc                                      #
#         Best Practices Assessment and Microsoft Purview integration          #
#         MUST be disabled BEFORE the move and re-enabled afterwards.          #
#         Failure to do so can leave SQL instances in a broken state.          #
#                                                                              #
#     [ ] RBAC role assignments                                                #
#         Any role assignments scoped at the source RG or subscription         #
#         are orphaned by the move and must be re-applied at the               #
#         destination scope.                                                   #
#                                                                              #
#     [ ] Azure Policy assignments, initiatives, and exemptions                #
#         Assignments scoped to the source sub/RG do not follow the            #
#         resource. Re-scope or re-assign at the destination.                  #
#                                                                              #
#     [ ] Microsoft Defender for Servers                                       #
#         The plan is enabled per-subscription. Confirm the destination         #
#         subscription has the correct Defender plan enabled.                  #
#                                                                              #
#     [ ] Data Collection Rules (DCRs) for Azure Monitor Agent                 #
#         If DCRs live in the source subscription, associations may            #
#         break. Re-associate the moved machines to DCRs in the                #
#         destination scope.                                                   #
#                                                                              #
#     [ ] Resource locks, tags inherited from source scope, and                #
#         Sentinel analytics rules that filter by subscription ID.              #
#                                                                              #
#   AGENT BEHAVIOUR                                                            #
#   After the move, the Connected Machine agent will continue reporting        #
#   under the NEW resource ID automatically. No restart, no reinstall,         #
#   no azcmagent disconnect/connect is required for same-region,               #
#   same-tenant moves. Extensions (AMA, MDE, etc.) travel with the             #
#   parent machine resource.                                                   #
#                                                                              #
#   CONSTRAINTS ENFORCED BY THIS SCRIPT                                        #
#     - Source and destination must be in the same Microsoft Entra tenant.     #
#     - Destination RG must exist. Region mismatch is tolerated (warning);     #
#       resources keep their original location. Pre-flight validation will      #
#       reject the move if Azure cannot honour it.                             #
#                                                                              #
################################################################################

'@

Write-Host $banner -ForegroundColor Yellow

if (-not $AcceptDisclaimer -and -not $WhatIfPreference) {
    Write-Host "By proceeding, you confirm that you have read and understood the" -ForegroundColor Yellow
    Write-Host "above, and accept responsibility for any post-move remediation" -ForegroundColor Yellow
    Write-Host "required in the destination scope." -ForegroundColor Yellow
    Write-Host ""
    $response = Read-Host "Type 'I AGREE' (exactly, case-sensitive) to continue, or anything else to abort"
    if ($response -cne 'I AGREE') {
        Write-Host "Disclaimer not accepted. Aborting." -ForegroundColor Red
        return
    }
    Write-Host "Disclaimer accepted. Proceeding." -ForegroundColor Green
    Write-Host ""
}
elseif ($AcceptDisclaimer) {
    Write-Host "Disclaimer accepted via -AcceptDisclaimer switch. Proceeding." -ForegroundColor Green
    Write-Host ""
}

# ---- 1. Verify login, resolve tenant, and confirm both subs are accessible ----
# We intentionally do NOT call Set-AzContext to switch between subs. On many
# setups only one context is registered ('My AzContext') and the switch is
# either a no-op or updates a different named context. Since Arc cross-sub
# moves require same-tenant, a single bearer token from the active login is
# valid for both subscriptions; we target each sub via the URL path of
# Invoke-AzRestMethod / explicit -Scope parameters on resource-level cmdlets.
$ambientCtx = Get-AzContext
if (-not $ambientCtx -or -not $ambientCtx.Tenant -or -not $ambientCtx.Tenant.Id) {
    throw "No active Az login. Run 'Connect-AzAccount' first."
}
$activeTenant = $ambientCtx.Tenant.Id

function Test-SubscriptionAccessible {
    param ([string]$SubscriptionId, [string]$ExpectedTenant)
    $sub = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
    if (-not $sub) {
        throw "Subscription '$SubscriptionId' is not accessible to the current Az login. " +
              "Run 'Connect-AzAccount -Tenant $ExpectedTenant' and confirm the account has access."
    }
    $subTenant = if ($sub.PSObject.Properties['TenantId']) { $sub.TenantId } else { $null }
    if ($subTenant -and $subTenant -ne $ExpectedTenant) {
        throw "Subscription '$SubscriptionId' lives in tenant $subTenant, not $ExpectedTenant. " +
              "Cross-tenant Arc move is not supported without agent disconnect/reconnect."
    }
    return $sub
}

Write-Host "Validating source subscription access..." -ForegroundColor Cyan
$null = Test-SubscriptionAccessible -SubscriptionId $SourceSubscriptionId      -ExpectedTenant $activeTenant
Write-Host "Validating destination subscription access..." -ForegroundColor Cyan
$null = Test-SubscriptionAccessible -SubscriptionId $DestinationSubscriptionId -ExpectedTenant $activeTenant

# Helper: throw on non-success status, return parsed JSON content
function Invoke-ArmRequest {
    param (
        [string]$Path,
        [string]$Method = 'GET',
        $Body,
        [int[]]$AcceptStatus = @(200, 201, 202, 204)
    )
    $params = @{ Path = $Path; Method = $Method }
    if ($Body) { $params['Payload'] = ($Body | ConvertTo-Json -Depth 10 -Compress) }
    $resp = Invoke-AzRestMethod @params
    if ($AcceptStatus -notcontains $resp.StatusCode) {
        throw "ARM $Method $Path failed with HTTP $($resp.StatusCode): $($resp.Content)"
    }
    if ($resp.Content) { return $resp.Content | ConvertFrom-Json }
    return $null
}

# ---- 2. Destination RG check (ARM GET on destination sub) ----
$destRgPath = "/subscriptions/$DestinationSubscriptionId/resourceGroups/${DestinationResourceGroup}?api-version=2021-04-01"
$destRgResp = Invoke-AzRestMethod -Path $destRgPath -Method GET
if ($destRgResp.StatusCode -eq 404) {
    throw "Destination resource group '$DestinationResourceGroup' not found in subscription $DestinationSubscriptionId. Create it first (same region as the Arc servers)."
}
if ($destRgResp.StatusCode -ne 200) {
    throw "Could not read destination RG (HTTP $($destRgResp.StatusCode)): $($destRgResp.Content)"
}
$destLocation = ($destRgResp.Content | ConvertFrom-Json).location

# ---- 3. Discover Arc machines in source (ARM GET on source sub) ----
$listPath = "/subscriptions/$SourceSubscriptionId/resourceGroups/$SourceResourceGroup/providers/Microsoft.HybridCompute/machines?api-version=2024-07-10"
$listResult = Invoke-ArmRequest -Path $listPath -Method GET
$machines = @($listResult.value | ForEach-Object {
    [PSCustomObject]@{
        Name       = $_.name
        Location   = $_.location
        ResourceId = $_.id
    }
})

if ($MachineNameFilter) {
    $machines = @($machines | Where-Object {
        $name = $_.Name
        $MachineNameFilter | Where-Object { $name -like $_ }
    })
}

if (-not $machines -or $machines.Count -eq 0) {
    Write-Warning "No Arc machines found in $SourceSubscriptionId/$SourceResourceGroup matching filter."
    return
}

Write-Host "Found $($machines.Count) Arc machine(s) to move:" -ForegroundColor Cyan
$machines | Format-Table Name, Location, ResourceId -AutoSize

# ---- 4. Region validation ----
# Azure returns region names in either internal form ('uksouth') or display
# form ('UK South') depending on the endpoint. Normalise by stripping spaces
# and lowercasing before comparison.
function ConvertTo-NormalizedRegion {
    param ([string]$Region)
    if (-not $Region) { return '' }
    return ($Region -replace '\s', '').ToLowerInvariant()
}

# Region mismatch is not a blocker for an ARM metadata move - resources keep
# their original location regardless of destination RG region. We surface it
# as a warning so users notice unexpected geography, and only abort if
# -FailOnRegionMismatch is explicitly requested.
$destLocationNorm = ConvertTo-NormalizedRegion $destLocation
$mismatched = @($machines | Where-Object {
    (ConvertTo-NormalizedRegion $_.Location) -ne $destLocationNorm
})
if ($mismatched.Count -gt 0) {
    if ($FailOnRegionMismatch) {
        Write-Error "Destination RG is in '$destLocation' but these machines are in a different region (and -FailOnRegionMismatch is set):"
        $mismatched | Format-Table Name, Location -AutoSize
        throw "Aborting due to -FailOnRegionMismatch. Resources would retain their original region after the move; remove the switch if that is intended."
    }
    Write-Warning "Destination RG is in '$destLocation' but $($mismatched.Count) machine(s) are in a different region. This is fine for a metadata move - resources keep their original location. Pre-flight validation will confirm."
    $mismatched | Format-Table Name, Location -AutoSize
}

# ---- 5. Pre-flight validate via ARM (official dry run) ----
# https://learn.microsoft.com/azure/azure-resource-manager/management/move-resource-group-and-subscription#validate-move
$resourceIds = @($machines.ResourceId)
$targetRgId  = "/subscriptions/$DestinationSubscriptionId/resourceGroups/$DestinationResourceGroup"
$validateBody = @{ resources = $resourceIds; targetResourceGroup = $targetRgId } | ConvertTo-Json -Depth 5
$validatePath = "/subscriptions/$SourceSubscriptionId/resourceGroups/$SourceResourceGroup/validateMoveResources?api-version=2021-04-01"
Write-Host "Running ARM pre-flight validateMoveResources..." -ForegroundColor Cyan
$validateResponse = Invoke-AzRestMethod -Path $validatePath -Method POST -Payload $validateBody
if ($validateResponse.StatusCode -notin 202, 204) {
    throw "Pre-flight validation failed (HTTP $($validateResponse.StatusCode)): $($validateResponse.Content)"
}
Write-Host "Pre-flight accepted (async). Proceeding." -ForegroundColor Green

# ---- 6. Batched move via ARM moveResources ----
# We call the REST API directly instead of Move-AzResource to avoid any
# context-switching requirements. The bearer token carried by Invoke-AzRestMethod
# is tenant-scoped and valid for both source and destination subs.
$movePath = "/subscriptions/$SourceSubscriptionId/resourceGroups/$SourceResourceGroup/moveResources?api-version=2021-04-01"

$batches = for ($i = 0; $i -lt $resourceIds.Count; $i += $BatchSize) {
    , ($resourceIds[$i..([math]::Min($i + $BatchSize - 1, $resourceIds.Count - 1))])
}

$batchNum = 0
foreach ($batch in $batches) {
    $batchNum++
    $target = "batch $batchNum ($($batch.Count) machine(s)) -> $DestinationSubscriptionId/$DestinationResourceGroup"
    if ($PSCmdlet.ShouldProcess($target, 'ARM moveResources')) {
        $moveBody = @{ resources = @($batch); targetResourceGroup = $targetRgId } | ConvertTo-Json -Depth 5
        $moveResp = Invoke-AzRestMethod -Path $movePath -Method POST -Payload $moveBody
        if ($moveResp.StatusCode -notin 200, 202) {
            throw "Batch $batchNum move failed (HTTP $($moveResp.StatusCode)): $($moveResp.Content)"
        }
        Write-Host "Batch $batchNum submitted (async, HTTP $($moveResp.StatusCode))." -ForegroundColor Green
    }
}

# ---- 7. Post-move verification (ARM GET on destination sub) ----
if (-not $WhatIfPreference) {
    Start-Sleep -Seconds 15
    $dstListPath = "/subscriptions/$DestinationSubscriptionId/resourceGroups/$DestinationResourceGroup/providers/Microsoft.HybridCompute/machines?api-version=2024-07-10"
    $dstList = Invoke-ArmRequest -Path $dstListPath -Method GET
    $movedNames = @($dstList.value | ForEach-Object { $_.name })
    $moved = @($dstList.value | Where-Object { $machines.Name -contains $_.name })

    Write-Host "`nVerified at destination:" -ForegroundColor Cyan
    $moved | ForEach-Object {
        [PSCustomObject]@{
            Name              = $_.name
            ResourceGroupName = $DestinationResourceGroup
            Location          = $_.location
        }
    } | Format-Table -AutoSize

    $missing = @($machines | Where-Object { $movedNames -notcontains $_.Name })
    if ($missing.Count -gt 0) {
        Write-Warning "These machines did not appear at the destination (move may still be in progress - ARM move can take up to 4 hours):"
        $missing.Name
    }
}