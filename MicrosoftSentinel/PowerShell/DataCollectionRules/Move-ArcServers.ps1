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
      2. Validates that the destination resource group exists and is in the same
         Azure region as every machine being moved (cross-region Arc moves
         require extension removal and re-registration, not a metadata move).
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
    receive the machines. Must already exist and must be in the same Azure
    region as every machine being moved.

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
    [switch]   $AcceptDisclaimer
)

$ErrorActionPreference = 'Stop'

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
#         The plan is enabled per-subscription. Confirm the destination        #
#         subscription has the correct Defender plan enabled.                  #
#                                                                              #
#     [ ] Data Collection Rules (DCRs) for Azure Monitor Agent                 #
#         If DCRs live in the source subscription, associations may            #
#         break. Re-associate the moved machines to DCRs in the                #
#         destination scope.                                                   #
#                                                                              #
#     [ ] Resource locks, tags inherited from source scope, and                #
#         Sentinel analytics rules that filter by subscription ID.             #
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
#     - Destination RG must exist and be in the same Azure region as           #
#       every machine being moved.                                             #
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

# ---- 1. Tenant check ----
# Pin each subscription to an explicit context object and pass it via
# -DefaultProfile to every Az cmdlet. Relying on the ambient context set
# by Set-AzContext is unreliable when multiple contexts are active — the
# switch can silently fail to take effect and subsequent cmdlets run
# against the wrong subscription.
#
# Set-AzContext's return value can be a stale snapshot depending on the Az
# module version; always follow with Get-AzContext to get the authoritative
# current context, and tolerate both .Id and .SubscriptionId property names
# that have existed in different Az versions.
function Resolve-AzContextForSubscription {
    param ([string]$SubscriptionId)

    # Verify the subscription is accessible to the current login first.
    # Set-AzContext -SubscriptionId silently no-ops if the sub isn't in the
    # account's enumerated contexts, leaving you on the previous sub.
    $sub = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
    if (-not $sub) {
        throw "Subscription '$SubscriptionId' is not accessible to the current Az login. " +
              "Run 'Get-AzSubscription' to see available subscriptions, or 'Connect-AzAccount -Tenant <tenantId>' to log in to the correct tenant."
    }

    # Pass the subscription object directly — more reliable than -SubscriptionId
    # because it forces Az.Accounts to build the context from a known-good source.
    Set-AzContext -Subscription $sub -WarningAction SilentlyContinue | Out-Null

    $ctx = Get-AzContext
    if (-not $ctx -or -not $ctx.Subscription) {
        throw "No Az context active after Set-AzContext. Run Connect-AzAccount first."
    }

    $ctxSub = $ctx.Subscription
    $resolvedId = $null
    if ($ctxSub.PSObject.Properties['Id']             -and $ctxSub.Id)             { $resolvedId = $ctxSub.Id }
    elseif ($ctxSub.PSObject.Properties['SubscriptionId'] -and $ctxSub.SubscriptionId) { $resolvedId = $ctxSub.SubscriptionId }

    if ($resolvedId -ne $SubscriptionId) {
        throw "Failed to switch Az context to $SubscriptionId (got '$resolvedId') despite the subscription being listed as accessible. This is a known Az.Accounts quirk — try 'Clear-AzContext -Force' followed by 'Connect-AzAccount'."
    }
    return $ctx
}

$srcCtx = Resolve-AzContextForSubscription -SubscriptionId $SourceSubscriptionId
$srcTenant = $srcCtx.Tenant.Id

$dstCtx = Resolve-AzContextForSubscription -SubscriptionId $DestinationSubscriptionId
$dstTenant = $dstCtx.Tenant.Id

if ($srcTenant -ne $dstTenant) {
    throw "Source tenant ($srcTenant) and destination tenant ($dstTenant) differ. Cross-tenant Arc move is not supported without agent disconnect/reconnect."
}

# ---- 2. Destination RG check ----
$destRg = Get-AzResourceGroup -Name $DestinationResourceGroup -DefaultProfile $dstCtx -ErrorAction SilentlyContinue
if (-not $destRg) {
    throw "Destination resource group '$DestinationResourceGroup' not found in subscription $DestinationSubscriptionId. Create it first (same region as the Arc servers)."
}
$destLocation = $destRg.Location

# ---- 3. Discover Arc machines in source ----
$machines = Get-AzResource `
    -ResourceGroupName $SourceResourceGroup `
    -ResourceType 'Microsoft.HybridCompute/machines' `
    -DefaultProfile $srcCtx

if ($MachineNameFilter) {
    $machines = $machines | Where-Object {
        $name = $_.Name
        $MachineNameFilter | Where-Object { $name -like $_ }
    }
}

if (-not $machines) {
    Write-Warning "No Arc machines found in $SourceSubscriptionId/$SourceResourceGroup matching filter."
    return
}

Write-Host "Found $($machines.Count) Arc machine(s) to move:" -ForegroundColor Cyan
$machines | Select-Object Name, Location, ResourceId | Format-Table -AutoSize

# ---- 4. Region validation ----
$badRegion = $machines | Where-Object { $_.Location -ne $destLocation }
if ($badRegion) {
    Write-Error "Destination RG is in '$destLocation' but these machines are in a different region. Cross-region move is NOT supported via Move-AzResource and requires agent reconnect:"
    $badRegion | Select-Object Name, Location | Format-Table -AutoSize
    throw "Aborting. Either create the destination RG in the matching region, or follow the cross-region procedure (disconnect + azcmagent connect) for these hosts."
}

# ---- 5. Pre-flight validate via ARM (official dry run) ----
# https://learn.microsoft.com/azure/azure-resource-manager/management/move-resource-group-and-subscription#validate-move
$resourceIds = @($machines.ResourceId)
$validateBody = @{
    resources           = $resourceIds
    targetResourceGroup = "/subscriptions/$DestinationSubscriptionId/resourceGroups/$DestinationResourceGroup"
} | ConvertTo-Json -Depth 5

$validatePath = "/subscriptions/$SourceSubscriptionId/resourceGroups/$SourceResourceGroup/validateMoveResources?api-version=2021-04-01"
Write-Host "Running ARM pre-flight validateMoveResources..." -ForegroundColor Cyan
$validateResponse = Invoke-AzRestMethod -Path $validatePath -Method POST -Payload $validateBody -DefaultProfile $srcCtx
if ($validateResponse.StatusCode -notin 202, 204) {
    throw "Pre-flight validation failed: $($validateResponse.Content)"
}
Write-Host "Pre-flight accepted (async). Proceeding." -ForegroundColor Green

# ---- 6. Batched move ----
$batches = for ($i = 0; $i -lt $resourceIds.Count; $i += $BatchSize) {
    , ($resourceIds[$i..([math]::Min($i + $BatchSize - 1, $resourceIds.Count - 1))])
}

$batchNum = 0
foreach ($batch in $batches) {
    $batchNum++
    $target = "batch $batchNum ($($batch.Count) machine(s)) -> $DestinationSubscriptionId/$DestinationResourceGroup"
    if ($PSCmdlet.ShouldProcess($target, 'Move-AzResource')) {
        Move-AzResource `
            -DestinationSubscriptionId $DestinationSubscriptionId `
            -DestinationResourceGroupName $DestinationResourceGroup `
            -ResourceId $batch `
            -DefaultProfile $srcCtx `
            -Force
        Write-Host "Batch $batchNum moved." -ForegroundColor Green
    }
}

# ---- 7. Post-move verification ----
if (-not $WhatIfPreference) {
    Start-Sleep -Seconds 15
    $moved = Get-AzResource `
        -ResourceGroupName $DestinationResourceGroup `
        -ResourceType 'Microsoft.HybridCompute/machines' `
        -DefaultProfile $dstCtx |
        Where-Object { $machines.Name -contains $_.Name }

    Write-Host "`nVerified at destination:" -ForegroundColor Cyan
    $moved | Select-Object Name, ResourceGroupName, Location | Format-Table -AutoSize

    $missing = $machines | Where-Object { $moved.Name -notcontains $_.Name }
    if ($missing) {
        Write-Warning "These machines did not appear at the destination (move may still be in progress - ARM move can take up to 4 hours):"
        $missing.Name
    }
}