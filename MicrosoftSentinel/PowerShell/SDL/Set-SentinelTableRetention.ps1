<#
.SYNOPSIS
    Manages Log Analytics / Microsoft Sentinel table retention settings via the
    Azure REST API (2025-07-01). Supports hot (interactive/Analytics) retention
    and total retention (hot + Data Lake tier), with a dry-run mode that shows
    exactly what would change — including a full data access impact assessment
    showing where data lives, how it's accessed, and transition recommendations.

.DESCRIPTION
    Uses the Tables - Create Or Update REST API:
    https://learn.microsoft.com/en-us/rest/api/loganalytics/tables/create-or-update

    Key retention concepts
    ─────────────────────
    • retentionInDays       → Interactive / "hot" retention in the Analytics tier.
                              Range: 4–730. Set to -1 to inherit the workspace default.
                              Data here is fully queryable at no per-query cost.

    • totalRetentionInDays  → Total lifespan of the data including time in the
                              Data Lake tier. Range: 4–4383 (≈12 years).
                              archiveRetentionInDays = total – hot (read-only, computed
                              by the API and shown in dry-run output).

    Sentinel Data Lake vs. legacy Archive
    ──────────────────────────────────────
    The classic Log Analytics "Archive" tier (cold long-term storage requiring
    explicit restore jobs) is SUPERSEDED by the Sentinel Data Lake (SDL) when
    the workspace is onboarded via the Defender portal. Understanding the
    transition is critical when changing retention settings:

    What happens at SDL onboarding:
      • Data ingested AFTER onboarding is mirrored to the lake at ingestion time.
        There is no separate archiving step for new data.
      • Mirroring is FORWARD-ONLY. Existing archive data is NOT retroactively
        migrated to the data lake. It remains in legacy archive.
      • The legacy archive billing meter switches to data lake pricing with a
        6:1 compression discount (≈1/6th the cost), even for data that hasn't
        physically moved.
      • No new data is written to legacy archive after onboarding — the archive
        is a static, draining pool that ages out per totalRetentionInDays.
      • Lake-tier data is queryable via KQL jobs and Spark notebooks without
        restore jobs. Real-time analytics rules do NOT run against lake data.

    Reducing analytics retention after SDL onboarding:
      • NO DATA IS LOST. Data always exists somewhere: analytics (hot), legacy
        archive, or data lake. Only the ACCESS METHOD changes.
      • Data that ages out of analytics but was ingested BEFORE SDL onboarding
        falls to legacy archive (restore/search job required).
      • Data that ages out of analytics but was ingested AFTER SDL onboarding
        is already mirrored in the lake (KQL job queryable, no restore needed).
      • The gap between SDL age and your analytics retention determines how long
        until the lake fully covers the rolling window. Use -DataLakeAgeDays to
        model this in the dry-run impact assessment.

    How retention modifications work (Azure Monitor behaviour):
      • When you SHORTEN total retention, Azure Monitor waits 30 days before
        removing data — giving you time to revert if the change was an error.
      • When you INCREASE total retention, the new period applies immediately to
        all data already ingested and not yet removed.
      • When you REDUCE analytics retention without changing total retention,
        Azure Monitor automatically treats the difference as long-term retention.
        Example: 180d analytics → 90d analytics with 180d total = 90d long-term
        retention is created automatically. No data is lost.
      • Setting analytics retention below 31 days does NOT reduce costs — 31 days
        of analytics retention are included in the ingestion price.

    API method — PATCH vs PUT:
      • This script uses PATCH, which only modifies properties you explicitly set.
      • PUT would reset any omitted property to its default — dangerous if you
        only want to change one of hot/total retention.

    Safe transition approach:
      • Set totalRetentionInDays FIRST to ensure the retention envelope is wide
        enough before reducing analytics retention.
      • Ideally wait until SDL has accumulated enough mirrored data to cover your
        desired analytics retention before reducing it.
      • Use -DryRun with -DataLakeAgeDays to see the exact impact before touching
        anything.

.PARAMETER SubscriptionId
    Azure Subscription ID containing the Log Analytics workspace.

.PARAMETER ResourceGroupName
    Resource group containing the workspace.

.PARAMETER WorkspaceName
    Log Analytics workspace name.

.PARAMETER TableNames
    One or more table names to update. Mutually exclusive with -AllTables.

.PARAMETER AllTables
    Enumerate ALL tables in the workspace and apply the retention settings to each
    one. Use -FilterPlan and/or -FilterTableType to narrow the scope.
    Mutually exclusive with -TableNames.

.PARAMETER FilterPlan
    When using -AllTables, only process tables whose current plan matches one of
    these values: Analytics, Basic, Auxiliary.
    Default: no filter (all plans).

.PARAMETER FilterTableType
    When using -AllTables, only process tables whose tableType matches one of
    these values: Microsoft, CustomLog, RestoredLogs, SearchResults.
    Default: no filter (all types).

.PARAMETER SkipEmpty
    When using -AllTables, skip tables that have never received data
    (lastDataReceivedOn is null or empty). This filters out the hundreds of
    pre-registered Microsoft table schemas that exist in every workspace but
    contain no rows.

.PARAMETER HotRetention
    Interactive (Analytics-tier / hot) retention period.
    Accepts human-friendly values matching the Azure portal dropdown:
      30d, 60d, 90d, 120d, 180d, 270d, 1y, 1.5y, 2y
    Or use 'default' to reset to the workspace default.
    Omit to leave unchanged.
    NOTE: For Basic and Auxiliary plan tables this property is read-only;
    it will be skipped automatically with a warning.

.PARAMETER TotalRetention
    Total retention period (hot + Data Lake / long-term).
    Accepts human-friendly values matching the Azure portal dropdown:
      30d, 60d, 90d, 120d, 180d, 270d, 1y, 1.5y, 2y, 3y, 4y, 5y,
      6y, 7y, 8y, 9y, 10y, 11y, 12y
    Or use 'default' to reset to match HotRetention (no long-term).
    Must be >= HotRetention. Omit to leave unchanged.

.PARAMETER DataLakeAgeDays
    Number of days since Sentinel Data Lake was enabled on this workspace.
    Used in -DryRun mode to calculate the data access impact assessment,
    showing exactly where data lives and what access method is available
    for each time window. If omitted, the impact assessment is skipped.

.PARAMETER DryRun
    Dry-run mode. Queries the current state of every target table and renders a
    diff table showing current vs. proposed values, plus a data access impact
    assessment if -DataLakeAgeDays is provided. No changes are made.

.PARAMETER Force
    Skips the interactive confirmation prompt when not in -DryRun mode.

.PARAMETER ThrottleMs
    Milliseconds to wait between API calls to avoid throttling. Default: 200.

.PARAMETER MaxRetries
    Maximum number of retry attempts for transient API failures (429, 503).
    Default: 3.

.PARAMETER ExportCsvPath
    Optional path to export the results summary as a CSV file.

.EXAMPLE
    # Dry-run with SDL impact assessment against ALL tables
    .\Set-SentinelTableRetention.ps1 `
        -SubscriptionId    "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName     "law-sentinel-prod" `
        -AllTables `
        -HotRetention       90d `
        -TotalRetention     2y `
        -DataLakeAgeDays    7 `
        -DryRun

.EXAMPLE
    # Apply to Analytics-plan tables only, export results
    .\Set-SentinelTableRetention.ps1 `
        -SubscriptionId    "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName     "law-sentinel-prod" `
        -AllTables `
        -FilterPlan        Analytics `
        -HotRetention       90d `
        -TotalRetention     2y `
        -Force `
        -ExportCsvPath     "C:\Temp\retention-results.csv"

.EXAMPLE
    # Specific tables with SDL impact assessment
    .\Set-SentinelTableRetention.ps1 `
        -SubscriptionId    "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName     "law-sentinel-prod" `
        -TableNames        "SigninLogs","AuditLogs","SecurityEvent" `
        -HotRetention       90d `
        -TotalRetention     5y `
        -DataLakeAgeDays    7 `
        -DryRun

.EXAMPLE
    # Reset hot retention to workspace default, set total to 1 year
    .\Set-SentinelTableRetention.ps1 `
        -SubscriptionId    "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName     "law-sentinel-prod" `
        -TableNames        "Syslog" `
        -HotRetention       default `
        -TotalRetention     1y `
        -DryRun

.NOTES
    Authentication : Uses the current Az context (Connect-AzAccount / az login).
                     The identity needs the Log Analytics Contributor role or higher
                     on the workspace.
    API Version    : 2025-07-01
    Author         : Toby G
    Requires       : Az.Accounts module (for token acquisition)
#>

[CmdletBinding(DefaultParameterSetName = 'SpecificTables')]
param (
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$WorkspaceName,

    # ── Table selection ──────────────────────────────────────────────────────
    [Parameter(Mandatory, ParameterSetName = 'SpecificTables')]
    [string[]]$TableNames,

    [Parameter(Mandatory, ParameterSetName = 'AllTables')]
    [switch]$AllTables,

    [Parameter(ParameterSetName = 'AllTables')]
    [ValidateSet('Analytics', 'Basic', 'Auxiliary')]
    [string[]]$FilterPlan,

    [Parameter(ParameterSetName = 'AllTables')]
    [ValidateSet('Microsoft', 'CustomLog', 'RestoredLogs', 'SearchResults')]
    [string[]]$FilterTableType,

    [Parameter(ParameterSetName = 'AllTables')]
    [switch]$SkipEmpty,

    # ── Retention ────────────────────────────────────────────────────────────
    # Accepts: 30d, 60d, 90d, 120d, 180d, 270d, 1y, 1.5y, 2y, etc.
    #          or 'default' to reset to workspace/hot default
    [string]$HotRetention,

    [string]$TotalRetention,

    # ── Data Lake transition ─────────────────────────────────────────────────
    [ValidateRange(0, 4383)]
    [int]$DataLakeAgeDays = -1,

    # ── Behaviour ────────────────────────────────────────────────────────────
    [switch]$DryRun,

    [switch]$Force,

    [int]$ThrottleMs = 200,

    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3,

    [string]$ExportCsvPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helpers ──────────────────────────────────────────────────────────────

# ── Allowed retention values (matching the Azure / Defender portal dropdowns) ─
$script:AllowedHotRetention = [ordered]@{
    '30d'     = 30
    '60d'     = 60
    '90d'     = 90
    '120d'    = 120
    '180d'    = 180
    '270d'    = 270
    '1y'      = 365
    '1.5y'    = 547
    '2y'      = 730
    'default' = -1
}

$script:AllowedTotalRetention = [ordered]@{
    '30d'     = 30
    '60d'     = 60
    '90d'     = 90
    '120d'    = 120
    '180d'    = 180
    '270d'    = 270
    '1y'      = 365
    '1.5y'    = 547
    '2y'      = 730
    '3y'      = 1095
    '4y'      = 1460
    '5y'      = 1826
    '6y'      = 2191
    '7y'      = 2556
    '8y'      = 2922
    '9y'      = 3288
    '10y'     = 3653
    '11y'     = 4018
    '12y'     = 4383
    'default' = -1
}

function ConvertTo-RetentionDays {
    <#
    .SYNOPSIS
        Converts a human-friendly retention string (e.g. '90d', '2y', 'default')
        to the integer days value expected by the API.
    #>
    param (
        [string]$Value,
        [System.Collections.Specialized.OrderedDictionary]$AllowedValues,
        [string]$ParameterName
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    $key = $Value.Trim().ToLower()

    if ($AllowedValues.Contains($key)) {
        return $AllowedValues[$key]
    }

    # Build a friendly list of allowed values for the error message
    $allowedList = ($AllowedValues.Keys | ForEach-Object {
        $days = $AllowedValues[$_]
        if ($_ -eq 'default') { 'default' }
        elseif ($days -ge 365) { "$_ ($days days)" }
        else { $_ }
    }) -join ', '

    throw "-$ParameterName '$Value' is not a valid retention period. " +
          "Allowed values: $allowedList"
}

function Format-RetentionFriendly ([int]$Days) {
    <#
    .SYNOPSIS
        Converts days back to the friendliest human-readable label.
    #>
    switch ($Days) {
        -1    { return 'workspace default' }
        30    { return '30d' }
        60    { return '60d' }
        90    { return '90d' }
        120   { return '120d' }
        180   { return '180d' }
        270   { return '270d' }
        365   { return '1y (365d)' }
        547   { return '1.5y (547d)' }
        730   { return '2y (730d)' }
        1095  { return '3y (1095d)' }
        1460  { return '4y (1460d)' }
        1826  { return '5y (1826d)' }
        2191  { return '6y (2191d)' }
        2556  { return '7y (2556d)' }
        2922  { return '8y (2922d)' }
        3288  { return '9y (3288d)' }
        3653  { return '10y (3653d)' }
        4018  { return '11y (4018d)' }
        4383  { return '12y (4383d)' }
        default { return "${Days}d" }
    }
}

function Get-AzBearerToken {
    <#
    .SYNOPSIS
        Acquires an Azure bearer token compatible with both Az.Accounts v3.x
        (returns plain string via .Token) and v4.x+ (returns SecureString).
    #>
    $context = Get-AzContext
    if (-not $context) { throw "No Az context found. Run Connect-AzAccount first." }

    $tokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"

    # Az.Accounts 4.x returns SecureString; 3.x returns plain string
    if ($tokenObj.Token -is [System.Security.SecureString]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenObj.Token)
        try   { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    return $tokenObj.Token
}

function Get-BaseUri ([string]$Sub, [string]$RG, [string]$WS) {
    "https://management.azure.com/subscriptions/$Sub/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS"
}

function Invoke-LAApi {
    <#
    .SYNOPSIS
        Calls the Log Analytics REST API with retry logic for transient failures
        (HTTP 429, 503, 504).
    #>
    param (
        [string]$Uri,
        [string]$Method = 'GET',
        [string]$Token,
        [hashtable]$Body,
        [int]$Retries = 3
    )
    $headers = @{
        'Authorization' = "Bearer $Token"
        'Content-Type'  = 'application/json'
    }
    $params = @{ Uri = $Uri; Method = $Method; Headers = $headers }
    if ($Body) { $params['Body'] = ($Body | ConvertTo-Json -Depth 10) }

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return Invoke-RestMethod @params
        }
        catch {
            $resp       = $_.Exception.Response
            $statusCode = $resp ? [int]$resp.StatusCode : 0
            $retryable  = $statusCode -in @(429, 503, 504)

            if ($retryable -and $attempt -lt $Retries) {
                $waitSec = [Math]::Pow(2, $attempt)  # Exponential backoff: 2, 4, 8...
                # Check for Retry-After header
                $retryAfter = $null
                if ($resp -and $resp.Headers) {
                    $retryAfter = $resp.Headers | Where-Object { $_.Key -eq 'Retry-After' } | Select-Object -First 1
                }
                if ($retryAfter) {
                    $waitSec = [Math]::Max($waitSec, [int]$retryAfter.Value[0])
                }
                Write-Warning "  API returned HTTP $statusCode — retrying in ${waitSec}s (attempt $attempt/$Retries)"
                Start-Sleep -Seconds $waitSec
                continue
            }

            $detail = $_.ErrorDetails ? $_.ErrorDetails.Message : $_.Exception.Message
            throw "API call failed [$Method $Uri] -- HTTP $statusCode : $detail"
        }
    }
}

function Get-AllWorkspaceTables {
    param ([string]$BaseUri, [string]$Token, [int]$Retries)
    Write-Host "  Enumerating workspace tables..." -NoNewline
    $uri    = "$BaseUri/tables?api-version=2025-07-01"
    $tables = [System.Collections.Generic.List[object]]::new()
    do {
        $response = Invoke-LAApi -Uri $uri -Method 'GET' -Token $Token -Retries $Retries
        foreach ($t in $response.value) { $tables.Add($t) }
        # nextLink only exists when there are additional pages — use PSObject
        # to safely check without tripping Set-StrictMode -Version Latest
        $uri = $response.PSObject.Properties['nextLink'] ? $response.nextLink : $null
    } while ($uri)
    Write-Host " $($tables.Count) tables found" -ForegroundColor Green
    return $tables
}

function Get-TableCurrentState {
    param ([string]$TableName, [string]$BaseUri, [string]$Token, [int]$Retries)
    $uri = "$BaseUri/tables/${TableName}?api-version=2025-07-01"
    try   { return (Invoke-LAApi -Uri $uri -Method 'GET' -Token $Token -Retries $Retries).properties }
    catch { Write-Warning "  Could not retrieve state for '$TableName': $_"; return $null }
}

function Format-RetentionValue ([Nullable[int]]$Days, [bool]$IsDefault) {
    if ($null -eq $Days) { return '(unchanged)' }
    if ($Days -eq -1)    { return 'workspace default' }
    $friendly = Format-RetentionFriendly $Days
    $suffix   = $IsDefault ? ' [ws-default]' : ''
    return "$friendly$suffix"
}

function Write-DiffTable {
    param ($TableName, $Current, [Nullable[int]]$NewHot, [Nullable[int]]$NewTotal)

    $curHot       = ($Current -and $Current.PSObject.Properties['retentionInDays'])             ? $Current.retentionInDays             : $null
    $curTotal     = ($Current -and $Current.PSObject.Properties['totalRetentionInDays'])        ? $Current.totalRetentionInDays        : $null
    $curLake      = ($Current -and $Current.PSObject.Properties['archiveRetentionInDays'])      ? $Current.archiveRetentionInDays      : $null
    $curPlan      = ($Current -and $Current.PSObject.Properties['plan'])                        ? $Current.plan                        : $null
    $curType      = ($Current -and $Current.PSObject.Properties['schema'] -and $Current.schema.PSObject.Properties['tableType']) ? $Current.schema.tableType : $null
    $hotDefault   = ($Current -and $Current.PSObject.Properties['retentionInDaysAsDefault'])    ? [bool]$Current.retentionInDaysAsDefault      : $false
    $totalDefault = ($Current -and $Current.PSObject.Properties['totalRetentionInDaysAsDefault']) ? [bool]$Current.totalRetentionInDaysAsDefault : $false

    $propHot   = ($null -ne $NewHot)   ? $NewHot   : $curHot
    $propTotal = ($null -ne $NewTotal) ? $NewTotal : $curTotal
    $propLake  = ($propHot -gt 0 -and $propTotal -gt 0) ? [Math]::Max(0, $propTotal - $propHot) : $null
    $changed   = ($propHot -ne $curHot) -or ($propTotal -ne $curTotal)

    if (-not $Current)  { $status = 'TABLE NOT FOUND' }
    elseif ($changed)   { $status = 'WILL CHANGE' }
    else                { $status = 'NO CHANGE' }

    $color = switch ($status) {
        'WILL CHANGE'    { 'Yellow' }
        'TABLE NOT FOUND'{ 'Red' }
        default          { 'Green' }
    }

    Write-Host "`n  [$status] " -ForegroundColor $color -NoNewline
    Write-Host "$TableName" -ForegroundColor Cyan -NoNewline
    Write-Host "  ($curPlan / $curType)" -ForegroundColor DarkGray

    Write-Host "  +------------------------------------+------------------------+------------------------+"
    Write-Host "  | Property                           | Current                | Proposed               |"
    Write-Host "  +------------------------------------+------------------------+------------------------+"

    $curLakeLabel  = $curLake  ? "$curLake days"  : 'none'
    $propLakeLabel = $propLake ? "$propLake days" : 'none / n/a'
    $rows = @(
        @{ Label = 'Hot retention (Analytics)';  Cur = (Format-RetentionValue $curHot $hotDefault);     Prop = (Format-RetentionValue $propHot $false) }
        @{ Label = 'Total retention';            Cur = (Format-RetentionValue $curTotal $totalDefault); Prop = (Format-RetentionValue $propTotal $false) }
        @{ Label = 'Data Lake / Archive days';   Cur = $curLakeLabel; Prop = $propLakeLabel }
    )
    foreach ($row in $rows) {
        Write-Host "  | $($row.Label.PadRight(34)) | $("$($row.Cur)".PadRight(22)) | $("$($row.Prop)".PadRight(22)) |"
    }
    Write-Host "  +------------------------------------+------------------------+------------------------+"

    return @{
        Changed  = $changed
        PropHot  = $propHot
        PropTotal = $propTotal
        PropLake = $propLake
        CurHot   = $curHot
        CurTotal = $curTotal
    }
}

function Write-DataAccessImpact {
    <#
    .SYNOPSIS
        Renders a data access impact assessment for a table, showing exactly where
        data lives across time windows and what access method is available.
    #>
    param (
        [string]$TableName,
        [int]$CurrentHot,
        [int]$ProposedHot,
        [int]$CurrentTotal,
        [int]$ProposedTotal,
        [int]$LakeAgeDays,
        [string]$Plan
    )

    # Skip impact for non-Analytics tables (Basic/Auxiliary have read-only hot retention)
    if ($Plan -in 'Basic', 'Auxiliary') {
        Write-Host "`n  Data Access Impact: " -NoNewline -ForegroundColor DarkCyan
        Write-Host "N/A — $Plan plan tables have fixed hot retention" -ForegroundColor DarkGray
        return
    }

    $isReduction    = $ProposedHot -lt $CurrentHot
    $effectiveTotal = $ProposedTotal

    Write-Host ""
    Write-Host "  Data Access Impact Assessment" -ForegroundColor DarkCyan
    Write-Host "  SDL age: $LakeAgeDays day(s) | Analytics: $CurrentHot → ${ProposedHot}d | Total: ${effectiveTotal}d" -ForegroundColor DarkGray
    Write-Host "  +---------------------------+---------------------+-----------------------------------------------+"
    Write-Host "  | Time Window               | Data Location       | Access Method                                 |"
    Write-Host "  +---------------------------+---------------------+-----------------------------------------------+"

    # Build time windows based on the proposed state and SDL age
    $windows = [System.Collections.Generic.List[hashtable]]::new()

    if ($isReduction) {
        # Window 1: 0 to min(LakeAge, ProposedHot) — covered by both Analytics + Lake
        $dualEnd = [Math]::Min($LakeAgeDays, $ProposedHot)
        if ($dualEnd -gt 0) {
            $windows.Add(@{
                Start  = 0
                End    = $dualEnd
                Where  = 'Analytics + Lake'
                Access = 'Full interactive KQL'
            })
        }

        # Window 2: LakeAge to ProposedHot — Analytics only (lake hasn't mirrored this yet)
        if ($LakeAgeDays -lt $ProposedHot) {
            $windows.Add(@{
                Start  = $dualEnd
                End    = $ProposedHot
                Where  = 'Analytics only'
                Access = 'Full interactive KQL (lake catching up)'
            })
        }

        # Window 3: ProposedHot to min(LakeAge, CurrentHot) — data that was in analytics,
        # now aged out, but lake has it if SDL was running when ingested
        if ($LakeAgeDays -gt $ProposedHot) {
            $lakeEnd = [Math]::Min($LakeAgeDays, $CurrentHot)
            if ($lakeEnd -gt $ProposedHot) {
                $windows.Add(@{
                    Start  = $ProposedHot
                    End    = $lakeEnd
                    Where  = 'Data Lake'
                    Access = 'KQL jobs (no restore needed)'
                })
            }
        }

        # Window 4: max(ProposedHot, LakeAge) to CurrentHot — the gap zone
        # Data ingested before SDL, now dropping out of analytics → legacy archive
        $gapStart = [Math]::Max($ProposedHot, $LakeAgeDays)
        $gapEnd   = $CurrentHot
        if ($gapStart -lt $gapEnd) {
            $windows.Add(@{
                Start  = $gapStart
                End    = $gapEnd
                Where  = 'Legacy Archive'
                Access = 'Restore / search job required'
            })
        }

        # Window 5: CurrentHot to CurrentTotal — already in archive/lake long-term
        if ($CurrentHot -lt $effectiveTotal) {
            $ltStart = [Math]::Max($CurrentHot, $gapEnd)
            if ($ltStart -lt $effectiveTotal) {
                $windows.Add(@{
                    Start  = $ltStart
                    End    = $effectiveTotal
                    Where  = 'Legacy Archive'
                    Access = 'Restore / search job required'
                })
            }
        }
    }
    else {
        # Not a reduction — simpler: just show the proposed state
        $dualEnd = [Math]::Min($LakeAgeDays, $ProposedHot)
        if ($dualEnd -gt 0) {
            $windows.Add(@{
                Start  = 0
                End    = $dualEnd
                Where  = 'Analytics + Lake'
                Access = 'Full interactive KQL'
            })
        }
        if ($LakeAgeDays -lt $ProposedHot) {
            $windows.Add(@{
                Start  = $dualEnd
                End    = $ProposedHot
                Where  = 'Analytics only'
                Access = 'Full interactive KQL (lake catching up)'
            })
        }
        if ($ProposedHot -lt $effectiveTotal) {
            $windows.Add(@{
                Start  = $ProposedHot
                End    = $effectiveTotal
                Where  = 'Data Lake + Archive'
                Access = 'KQL jobs / restore (depends on SDL age)'
            })
        }
    }

    # Deduplicate and merge overlapping windows, then render
    foreach ($w in $windows) {
        $label  = "$($w.Start)–$($w.End) days ago"
        $where  = $w.Where
        $access = $w.Access
        Write-Host "  | $($label.PadRight(25)) | $($where.PadRight(19)) | $($access.PadRight(45)) |"
    }

    Write-Host "  +---------------------------+---------------------+-----------------------------------------------+"

    # ── Recommendations & warnings ────────────────────────────────────────
    $warnings = [System.Collections.Generic.List[string]]::new()
    $recommendations = [System.Collections.Generic.List[string]]::new()

    if ($isReduction) {
        # Calculate the interactive gap
        $gapDays = [Math]::Max(0, $ProposedHot - $LakeAgeDays)
        $daysUntilFullCoverage = [Math]::Max(0, $ProposedHot - $LakeAgeDays)
        $fullCoverageDate = (Get-Date).AddDays($daysUntilFullCoverage).ToString('yyyy-MM-dd')

        if ($LakeAgeDays -lt $ProposedHot) {
            $warnings.Add(
                "Interactive gap: Lake has $LakeAgeDays days of mirrored data but analytics " +
                "retention is $ProposedHot days. Lake will fully cover the rolling window " +
                "in ~$daysUntilFullCoverage days ($fullCoverageDate)."
            )
        }

        if ($LakeAgeDays -lt $CurrentHot) {
            $archiveWindowStart = [Math]::Max($ProposedHot, $LakeAgeDays)
            $archiveWindowEnd   = $CurrentHot
            if ($archiveWindowStart -lt $archiveWindowEnd) {
                $archiveWindowDays = $archiveWindowEnd - $archiveWindowStart
                $warnings.Add(
                    "Legacy archive gap: ~$archiveWindowDays days of data ($archiveWindowStart–$archiveWindowEnd " +
                    "days old) will only be accessible via restore/search jobs. This data was " +
                    "ingested before SDL and will NOT migrate to the lake — it ages out naturally."
                )
            }
        }

        # Safe transition recommendation
        $safeDaysToWait = [Math]::Max(0, $CurrentHot - $LakeAgeDays)
        $safeDate       = (Get-Date).AddDays($safeDaysToWait).ToString('yyyy-MM-dd')

        if ($LakeAgeDays -lt $CurrentHot) {
            $recommendations.Add(
                "SAFEST: Wait $safeDaysToWait more days (until $safeDate) before reducing analytics " +
                "retention. By then the lake will have $CurrentHot days of mirrored data, fully " +
                "covering the current analytics window with no access gaps."
            )
            $recommendations.Add(
                "ACCEPTABLE: Apply now if you can tolerate restore-job access for historical " +
                "data older than $LakeAgeDays days. No data is lost — only the access method " +
                "changes. Ensure totalRetentionInDays ($effectiveTotal) is set high enough first."
            )
        }
        else {
            $recommendations.Add(
                "SAFE TO PROCEED: SDL has been running for $LakeAgeDays days, which fully covers " +
                "the current $CurrentHot-day analytics window. All data that rolls out of analytics " +
                "already has a mirrored copy in the lake."
            )
        }

        # Warn about data that won't ever reach the lake
        $warnings.Add(
            "NO DATA LOSS: All data remains accessible. Data always exists in analytics (hot), " +
            "legacy archive, or data lake. Only the access convenience changes."
        )
        $warnings.Add(
            "LEGACY ARCHIVE IS STATIC: No new data enters legacy archive after SDL onboarding. " +
            "Existing archive data stays put, gets the 6:1 billing discount, and ages out per " +
            "totalRetentionInDays ($effectiveTotal days)."
        )

        # Azure Monitor retention modification behaviour
        $longTermDays = $effectiveTotal - $ProposedHot
        if ($longTermDays -gt 0) {
            $warnings.Add(
                "AUTO-RECLASSIFICATION: Reducing analytics from $CurrentHot to $ProposedHot days " +
                "with total retention at $effectiveTotal days means Azure Monitor will automatically " +
                "treat the remaining $longTermDays days as long-term retention. Data aged $ProposedHot–$effectiveTotal " +
                "days is reclassified, not deleted."
            )
        }

        if ($ProposedTotal -lt $CurrentTotal) {
            $warnings.Add(
                "30-DAY SAFETY NET: You are reducing total retention ($CurrentTotal → $ProposedTotal days). " +
                "Azure Monitor waits 30 days before removing data past the new boundary — you can " +
                "revert within that window if this was an error."
            )
        }
    }

    # Render warnings
    if ($warnings.Count -gt 0) {
        Write-Host ""
        foreach ($w in $warnings) {
            # Determine colour: info vs warning
            if ($w.StartsWith('NO DATA LOSS') -or $w.StartsWith('LEGACY ARCHIVE') -or $w.StartsWith('AUTO-RECLASSIFICATION')) {
                Write-Host "  [i] " -ForegroundColor Cyan -NoNewline
                Write-Host $w -ForegroundColor DarkGray
            }
            elseif ($w.StartsWith('30-DAY SAFETY NET')) {
                Write-Host "  [i] " -ForegroundColor Green -NoNewline
                Write-Host $w -ForegroundColor Green
            }
            else {
                Write-Host "  [!] " -ForegroundColor Yellow -NoNewline
                Write-Host $w -ForegroundColor Yellow
            }
        }
    }

    # Render recommendations
    if ($recommendations.Count -gt 0) {
        Write-Host ""
        Write-Host "  Recommendations:" -ForegroundColor Green
        foreach ($r in $recommendations) {
            if ($r.StartsWith('SAFEST')) {
                Write-Host "  >>> " -ForegroundColor Green -NoNewline
                Write-Host $r -ForegroundColor Green
            }
            elseif ($r.StartsWith('SAFE TO PROCEED')) {
                Write-Host "  >>> " -ForegroundColor Green -NoNewline
                Write-Host $r -ForegroundColor Green
            }
            else {
                Write-Host "  >>> " -ForegroundColor DarkYellow -NoNewline
                Write-Host $r -ForegroundColor DarkYellow
            }
        }
    }
}

#endregion

#region ── Validation ───────────────────────────────────────────────────────────

# Convert friendly retention strings to API integer values
$HotRetentionDays   = ConvertTo-RetentionDays -Value $HotRetention   -AllowedValues $script:AllowedHotRetention   -ParameterName 'HotRetention'
$TotalRetentionDays = ConvertTo-RetentionDays -Value $TotalRetention -AllowedValues $script:AllowedTotalRetention -ParameterName 'TotalRetention'

if ($null -eq $HotRetentionDays -and $null -eq $TotalRetentionDays) {
    throw "At least one of -HotRetention or -TotalRetention must be specified."
}
if ($null -ne $HotRetentionDays -and $null -ne $TotalRetentionDays) {
    if ($HotRetentionDays -ne -1 -and $TotalRetentionDays -ne -1 -and $TotalRetentionDays -lt $HotRetentionDays) {
        throw "-TotalRetention resolves to $TotalRetentionDays days which is less than " +
              "-HotRetention ($HotRetentionDays days). Total must be >= Hot."
    }
}
if ($null -ne $HotRetentionDays -and $null -ne $TotalRetentionDays) {
    if ($HotRetentionDays -eq -1 -and $TotalRetentionDays -eq -1) {
        Write-Warning "Both -HotRetention and -TotalRetention are set to 'default'. The resulting retention depends entirely on the workspace configuration."
    }
}

# Warn about the 31-day cost floor for analytics retention
if ($null -ne $HotRetentionDays -and $HotRetentionDays -ge 4 -and $HotRetentionDays -lt 31) {
    Write-Warning ("Analytics retention set to $HotRetentionDays days. Note: 31 days of analytics " +
        "retention are included in the ingestion price — setting below 31 days does NOT reduce costs.")
}

#endregion

#region ── Main ─────────────────────────────────────────────────────────────────

Write-Host "`n+==================================================================+" -ForegroundColor Cyan
Write-Host   "|     Set-SentinelTableRetention  |  Log Analytics 2025-07-01     |" -ForegroundColor Cyan
Write-Host   "+==================================================================+`n" -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "  MODE: DRY-RUN -- no changes will be made`n" -ForegroundColor Yellow
}

Write-Host "  Workspace   : $WorkspaceName"
Write-Host "  Resource    : $ResourceGroupName / $SubscriptionId"
if ($AllTables) {
    $scopeLabel = "ALL TABLES"
    if ($FilterPlan)      { $scopeLabel += "  [plan: $($FilterPlan -join ', ')]" }
    if ($FilterTableType) { $scopeLabel += "  [type: $($FilterTableType -join ', ')]" }
    if ($SkipEmpty)       { $scopeLabel += "  [skip-empty]" }
    Write-Host "  Scope       : $scopeLabel"
} else {
    Write-Host "  Tables      : $($TableNames -join ', ')"
}
if ($null -ne $HotRetentionDays)   { Write-Host "  Hot target  : $(Format-RetentionFriendly $HotRetentionDays)" }
if ($null -ne $TotalRetentionDays) { Write-Host "  Total target: $(Format-RetentionFriendly $TotalRetentionDays)" }
if ($DataLakeAgeDays -ge 0)        { Write-Host "  SDL age     : $DataLakeAgeDays days" -ForegroundColor DarkCyan }
Write-Host ""

# Acquire token
Write-Host "  Acquiring Azure bearer token..." -NoNewline
$token   = Get-AzBearerToken
Write-Host " OK" -ForegroundColor Green

$baseUri = Get-BaseUri -Sub $SubscriptionId -RG $ResourceGroupName -WS $WorkspaceName

# ── Build working table list ──────────────────────────────────────────────────
if ($AllTables) {
    $allTableObjects = Get-AllWorkspaceTables -BaseUri $baseUri -Token $token -Retries $MaxRetries

    if ($FilterPlan) {
        $allTableObjects = @($allTableObjects | Where-Object { $_.properties.plan -in $FilterPlan })
        Write-Host "  After plan filter    : $($allTableObjects.Count) tables"
    }
    if ($FilterTableType) {
        $allTableObjects = @($allTableObjects | Where-Object { $_.properties.schema.tableType -in $FilterTableType })
        Write-Host "  After type filter    : $($allTableObjects.Count) tables"
    }
    if ($SkipEmpty) {
        # Query the Usage table to find which tables have actually ingested data.
        # This is definitive — the list API doesn't return lastDataReceivedOn in
        # bulk, so we ask the workspace directly with a single KQL query.
        Write-Host "  Querying Usage table for active tables..." -NoNewline
        $queryUri  = "$baseUri/api/query?api-version=2020-08-01"
        $queryBody = @{ query = "Usage | where TimeGenerated > ago(90d) | distinct DataType" }
        try {
            $queryResp   = Invoke-LAApi -Uri $queryUri -Method 'POST' -Token $token -Body $queryBody -Retries $MaxRetries
            $activeTables = @($queryResp.tables[0].rows | ForEach-Object { $_[0] })
            Write-Host " $($activeTables.Count) active tables" -ForegroundColor Green

            $allTableObjects = @($allTableObjects | Where-Object { $_.name -in $activeTables })
            Write-Host "  After empty filter   : $($allTableObjects.Count) tables (with data)"
        }
        catch {
            Write-Warning "  Could not query Usage table: $_"
            Write-Warning "  Falling back to all tables (SkipEmpty filter skipped)"
        }
    }

    $resolvedTableNames = @($allTableObjects | ForEach-Object { $_.name })
    Write-Host "  Processing           : $($resolvedTableNames.Count) tables`n" -ForegroundColor Cyan
} else {
    $allTableObjects    = $null
    $resolvedTableNames = $TableNames
}

$results         = [System.Collections.Generic.List[PSCustomObject]]::new()
$changeCount     = 0
$skipCount       = 0
$errorCount      = 0
$skippedReadOnly = 0
$tableIndex      = 0
$totalTables     = @($resolvedTableNames).Count

Write-Host "  Fetching current state and computing diffs...`n" -ForegroundColor DarkCyan

foreach ($tableName in $resolvedTableNames) {

    $tableIndex++
    $pct = [int](($tableIndex / $totalTables) * 100)
    Write-Progress -Activity "Processing tables" `
                   -Status "$tableIndex / $totalTables  ($pct%)  -- $tableName" `
                   -PercentComplete $pct

    Start-Sleep -Milliseconds $ThrottleMs

    # Reuse list-response properties when AllTables (saves API calls at scale)
    if ($allTableObjects) {
        $cachedObj = $allTableObjects | Where-Object { $_.name -eq $tableName } | Select-Object -First 1
        $current   = $cachedObj ? $cachedObj.properties : $null
    } else {
        $current = Get-TableCurrentState -TableName $tableName -BaseUri $baseUri -Token $token -Retries $MaxRetries
    }

    if (-not $current) {
        $results.Add([PSCustomObject]@{
            Table         = $tableName
            Plan          = 'N/A'
            TableType     = 'N/A'
            CurrentHot    = 'N/A'
            CurrentTotal  = 'N/A'
            ProposedHot   = 'N/A'
            ProposedTotal = 'N/A'
            LakeDays      = 'N/A'
            Status        = 'ERROR - not found or inaccessible'
        })
        $errorCount++
        continue
    }

    $curPlan  = $current.PSObject.Properties['plan'] ? $current.plan : $null
    $curType  = ($current.PSObject.Properties['schema'] -and $current.schema.PSObject.Properties['tableType']) ? $current.schema.tableType : $null
    $curHot   = $current.PSObject.Properties['retentionInDays'] ? $current.retentionInDays : $null
    $curTotal = $current.PSObject.Properties['totalRetentionInDays'] ? $current.totalRetentionInDays : $null
    $curLake  = $current.PSObject.Properties['archiveRetentionInDays'] ? $current.archiveRetentionInDays : $null

    # Basic / Auxiliary tables have read-only retentionInDays — skip hot silently
    $effectiveHot = $HotRetentionDays
    if ($curPlan -in 'Basic', 'Auxiliary' -and $null -ne $HotRetentionDays) {
        Write-Verbose "  '$tableName' is $curPlan plan -- HotRetentionDays is read-only, skipping"
        $effectiveHot = $null
        $skippedReadOnly++
    }

    $propHot   = ($null -ne $effectiveHot)        ? $effectiveHot        : $curHot
    $propTotal = ($null -ne $TotalRetentionDays)  ? $TotalRetentionDays  : $curTotal
    $propLake  = ($propHot -gt 0 -and $propTotal -gt 0) ? [Math]::Max(0, $propTotal - $propHot) : $curLake

    $willChange = ($propHot -ne $curHot) -or ($propTotal -ne $curTotal)

    if ($DryRun -or $willChange) {
        $diffResult = Write-DiffTable -TableName $tableName -Current $current `
            -NewHot $effectiveHot -NewTotal $TotalRetentionDays

        # Show data access impact assessment in dry-run mode when SDL age is known
        if ($DryRun -and $DataLakeAgeDays -ge 0 -and $willChange) {
            Write-DataAccessImpact `
                -TableName    $tableName `
                -CurrentHot   $curHot `
                -ProposedHot  $propHot `
                -CurrentTotal $curTotal `
                -ProposedTotal $propTotal `
                -LakeAgeDays  $DataLakeAgeDays `
                -Plan         $curPlan
        }
    }

    if (-not $willChange) {
        $results.Add([PSCustomObject]@{
            Table         = $tableName
            Plan          = $curPlan
            TableType     = $curType
            CurrentHot    = $curHot
            CurrentTotal  = $curTotal
            ProposedHot   = $propHot
            ProposedTotal = $propTotal
            LakeDays      = $curLake
            Status        = 'Skipped - already at desired state'
        })
        $skipCount++
        continue
    }

    if ($DryRun) {
        $results.Add([PSCustomObject]@{
            Table         = $tableName
            Plan          = $curPlan
            TableType     = $curType
            CurrentHot    = $curHot
            CurrentTotal  = $curTotal
            ProposedHot   = $propHot
            ProposedTotal = $propTotal
            LakeDays      = $propLake
            Status        = 'DryRun - would change'
        })
        $changeCount++
        continue
    }

    # ── Apply ──
    if (-not $Force -and -not $PSCmdlet.ShouldProcess($tableName, "Update retention settings")) {
        $results.Add([PSCustomObject]@{
            Table         = $tableName
            Plan          = $curPlan
            TableType     = $curType
            CurrentHot    = $curHot
            CurrentTotal  = $curTotal
            ProposedHot   = $propHot
            ProposedTotal = $propTotal
            LakeDays      = $curLake
            Status        = 'Skipped - user declined'
        })
        $skipCount++
        continue
    }

    $body = @{ properties = @{} }
    if ($null -ne $effectiveHot)       { $body.properties['retentionInDays']      = $effectiveHot }
    if ($null -ne $TotalRetentionDays) { $body.properties['totalRetentionInDays'] = $TotalRetentionDays }

    # Use PATCH (not PUT) — PATCH only modifies properties explicitly included
    # in the body. PUT resets omitted properties to their defaults, which would
    # be dangerous when only changing one of hot/total retention.
    $patchUri = "$baseUri/tables/${tableName}?api-version=2025-07-01"

    try {
        Write-Host "`n  Applying '$tableName'..." -NoNewline
        $response  = Invoke-LAApi -Uri $patchUri -Method 'PATCH' -Token $token -Body $body -Retries $MaxRetries
        $respProps = ($response -and $response.PSObject.Properties['properties']) ? $response.properties : $null
        $provState = ($respProps -and $respProps.PSObject.Properties['provisioningState']) ? $respProps.provisioningState : 'Unknown'

        $statusMsg = ($provState -eq 'Succeeded') ? 'Success' : "Pending - $provState"
        $msgColor  = ($provState -eq 'Succeeded') ? 'Green'   : 'Yellow'
        Write-Host " $provState" -ForegroundColor $msgColor

        if ($provState -in 'Updating', 'InProgress') {
            Write-Host "    The API accepted the change asynchronously (HTTP 202)." -ForegroundColor DarkYellow
            Write-Host "    Re-run with -DryRun to verify the final state once provisioning completes." -ForegroundColor DarkYellow
        }

        $respHot   = ($respProps -and $respProps.PSObject.Properties['retentionInDays'])      ? $respProps.retentionInDays      : $propHot
        $respTotal = ($respProps -and $respProps.PSObject.Properties['totalRetentionInDays'])  ? $respProps.totalRetentionInDays  : $propTotal
        $respLake  = ($respProps -and $respProps.PSObject.Properties['archiveRetentionInDays'])? $respProps.archiveRetentionInDays : $propLake

        $results.Add([PSCustomObject]@{
            Table         = $tableName
            Plan          = $curPlan
            TableType     = $curType
            CurrentHot    = $curHot
            CurrentTotal  = $curTotal
            ProposedHot   = $respHot
            ProposedTotal = $respTotal
            LakeDays      = $respLake
            Status        = $statusMsg
        })
        $changeCount++
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Warning "  Error updating '$tableName': $_"
        $results.Add([PSCustomObject]@{
            Table         = $tableName
            Plan          = $curPlan
            TableType     = $curType
            CurrentHot    = $curHot
            CurrentTotal  = $curTotal
            ProposedHot   = $propHot
            ProposedTotal = $propTotal
            LakeDays      = $curLake
            Status        = "Error: $($_.Exception.Message)"
        })
        $errorCount++
    }

    Start-Sleep -Milliseconds $ThrottleMs
}

Write-Progress -Activity "Processing tables" -Completed

#endregion

#region ── Summary ──────────────────────────────────────────────────────────────

Write-Host "`n+==================================================================+" -ForegroundColor Cyan
Write-Host   "|                          SUMMARY                                |" -ForegroundColor Cyan
Write-Host   "+==================================================================+"

if ($DryRun) {
    Write-Host "  Tables that WOULD change             : $changeCount" -ForegroundColor Yellow
    Write-Host "  Tables with no change needed         : $skipCount"   -ForegroundColor Green
    Write-Host "  Hot retention skipped (Basic/Aux)    : $skippedReadOnly" -ForegroundColor DarkYellow
    $errColor = $errorCount ? 'Red' : 'White'
    Write-Host "  Errors / not found                   : $errorCount"  -ForegroundColor $errColor
    Write-Host ""
    Write-Host "  Run without -DryRun to apply these changes." -ForegroundColor Cyan

    if ($DataLakeAgeDays -ge 0 -and $changeCount -gt 0) {
        Write-Host ""
        Write-Host "  ── Sentinel Data Lake Transition Summary ──" -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "  SDL has been running for $DataLakeAgeDays day(s)." -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "  Key facts to remember:" -ForegroundColor White
        Write-Host "    • NO DATA IS LOST when reducing analytics retention." -ForegroundColor Green
        Write-Host "      Data always exists in analytics, legacy archive, or data lake." -ForegroundColor Green
        Write-Host "    • Legacy archive is a STATIC pool — no new data enters after SDL" -ForegroundColor White
        Write-Host "      onboarding. Existing archive data ages out per totalRetentionInDays." -ForegroundColor White
        Write-Host "    • Archive data is NOT migrated to the lake. Mirroring is forward-only." -ForegroundColor White
        Write-Host "    • Archive billing switches to lake pricing (6:1 compression discount)" -ForegroundColor White
        Write-Host "      even for data that hasn't physically moved." -ForegroundColor White
        Write-Host "    • The lake fills up day-by-day from the onboarding date. After" -ForegroundColor White
        Write-Host "      $DataLakeAgeDays days, the lake has $DataLakeAgeDays days of mirrored data." -ForegroundColor White
        Write-Host ""
        Write-Host "  Access methods by data location:" -ForegroundColor White
        Write-Host "    Analytics (hot)  → Full interactive KQL, no per-query cost" -ForegroundColor Green
        Write-Host "    Data Lake        → KQL jobs, Spark notebooks (no restore needed)" -ForegroundColor DarkCyan
        Write-Host "    Legacy Archive   → Restore / search job required (slower, per-GB cost)" -ForegroundColor DarkYellow
        Write-Host ""
    }
} else {
    Write-Host "  Tables changed                       : $changeCount" -ForegroundColor Green
    Write-Host "  Tables skipped (no change needed)    : $skipCount"
    Write-Host "  Hot retention skipped (Basic/Aux)    : $skippedReadOnly" -ForegroundColor DarkYellow
    $errColor = $errorCount ? 'Red' : 'White'
    Write-Host "  Errors                               : $errorCount"  -ForegroundColor $errColor
}

Write-Host ""
$results | Format-Table Table, Plan, TableType, CurrentHot, CurrentTotal, ProposedHot, ProposedTotal, LakeDays, Status -AutoSize

if ($ExportCsvPath) {
    try {
        $results | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n  Results exported to: $ExportCsvPath" -ForegroundColor Cyan
    }
    catch {
        Write-Warning "  Failed to export CSV: $_"
    }
}

#endregion