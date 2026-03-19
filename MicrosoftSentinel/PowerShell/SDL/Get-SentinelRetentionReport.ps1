<#
.SYNOPSIS
    Generates an HTML retention assessment report for a Log Analytics / Microsoft
    Sentinel workspace. Read-only — no changes are made.

.DESCRIPTION
    Queries all (or selected) tables in a workspace via the Azure REST API
    (2025-07-01), computes proposed retention changes, and produces a self-contained
    HTML report with:

      • Executive summary with table counts and change breakdown
      • Retention diff table (current vs proposed) with filtering and sorting
      • Per-table data access impact assessment when Sentinel Data Lake age is provided
      • Sentinel Data Lake transition summary and recommendations

    This script is read-only. It never calls PATCH/PUT — it only reads table
    metadata and renders the results into an HTML file.

    See Set-SentinelTableRetention.ps1 (v1) for the script that applies changes.

.PARAMETER SubscriptionId
    Azure Subscription ID containing the Log Analytics workspace.

.PARAMETER ResourceGroupName
    Resource group containing the workspace.

.PARAMETER WorkspaceName
    Log Analytics workspace name.

.PARAMETER TableNames
    One or more table names to report on. Mutually exclusive with -AllTables.

.PARAMETER AllTables
    Report on ALL tables in the workspace. Use -FilterPlan, -FilterTableType,
    and/or -SkipEmpty to narrow the scope.

.PARAMETER FilterPlan
    When using -AllTables, only include tables whose plan matches: Analytics,
    Basic, Auxiliary.

.PARAMETER FilterTableType
    When using -AllTables, only include tables whose tableType matches:
    Microsoft, CustomLog, RestoredLogs, SearchResults.

.PARAMETER SkipEmpty
    When using -AllTables, skip tables that have not ingested data in the last
    90 days (queried via the Usage table).

.PARAMETER HotRetention
    Proposed interactive (hot) retention. Accepts: 30d, 60d, 90d, 120d, 180d,
    270d, 1y, 1.5y, 2y, or 'default'.

.PARAMETER TotalRetention
    Proposed total retention. Accepts: 30d–12y or 'default'. Must be >= HotRetention.

.PARAMETER DataLakeAgeDays
    Days since Sentinel Data Lake was enabled. Used to compute the data access
    impact assessment per table. If omitted, impact assessment is skipped.

.PARAMETER OutputPath
    Path for the HTML report file. Defaults to
    SentinelRetentionReport_<workspace>_<timestamp>.html in the current directory.

.PARAMETER AnalyticsIngestionCostPerGB
    Analytics tier ingestion cost in USD per GB. Default: 2.30 (US East, simplified
    commitment tier effective rate). Pay-as-you-go is 4.30/GB in most regions — set
    this to match your actual pricing tier. Used in the Lake Migration Cost Analysis tab.

.PARAMETER LakeIngestionCostPerGB
    Sentinel Data Lake ingestion + data processing cost in USD per GB. Default: 0.15
    (ingestion 0.05 + processing 0.10, US East). Used in the Lake Migration Cost Analysis tab.

.PARAMETER LakeScanCostPerGB
    Sentinel Data Lake KQL query scan cost in USD per GB. Default: 0.005 (US East).
    Used in the Lake Migration Cost Analysis tab.

.PARAMETER ThrottleMs
    Milliseconds between API calls. Default: 200.

.PARAMETER MaxRetries
    Retry attempts for transient API failures. Default: 3.

.EXAMPLE
    .\Get-SentinelRetentionReport.ps1 `
        -SubscriptionId    "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName     "law-sentinel-prod" `
        -AllTables `
        -SkipEmpty `
        -HotRetention       90d `
        -TotalRetention     5y `
        -DataLakeAgeDays    7

    Full report with all tables, 90-day hot retention, 5-year total retention,
    and data access impact assessment for a workspace with Data Lake enabled 7 days ago.

.EXAMPLE
    .\Get-SentinelRetentionReport.ps1 `
        -SubscriptionId    "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName     "law-sentinel-prod" `
        -TableNames        "SigninLogs", "AADNonInteractiveUserSignInLogs"

    Report on specific tables only, using default retention settings.

.EXAMPLE
    .\Get-SentinelRetentionReport.ps1 `
        -SubscriptionId    "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName     "law-sentinel-prod" `
        -AllTables `
        -SkipEmpty `
        -FilterPlan         Analytics `
        -HotRetention       90d `
        -TotalRetention     2y

    Report only Analytics-plan tables that have ingested data in the last 90 days.

.EXAMPLE
    .\Get-SentinelRetentionReport.ps1 `
        -SubscriptionId           "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName        "rg-sentinel" `
        -WorkspaceName            "law-sentinel-prod" `
        -AllTables `
        -SkipEmpty `
        -HotRetention              90d `
        -TotalRetention            5y `
        -DataLakeAgeDays           7 `
        -AnalyticsIngestionCostPerGB 4.30 `
        -LakeIngestionCostPerGB     0.15 `
        -LakeScanCostPerGB          0.005

    Full report using pay-as-you-go Analytics pricing (4.30/GB) instead of the
    default commitment tier rate (2.30/GB). The Lake Migration Cost Analysis tab
    uses these values to calculate whether tables are cheaper in Analytics or
    Sentinel Data Lake tier. Adjust all three cost parameters to match your
    pricing tier and Azure region.

.EXAMPLE
    .\Get-SentinelRetentionReport.ps1 `
        -SubscriptionId    "00000000-0000-0000-0000-000000000000" `
        -ResourceGroupName "rg-sentinel" `
        -WorkspaceName     "law-sentinel-prod" `
        -AllTables `
        -SkipEmpty `
        -HotRetention       90d `
        -TotalRetention     5y `
        -OutputPath         "C:\Reports\sentinel-retention.html"

    Save the report to a specific file path instead of the default location.

.NOTES
    Authentication : Uses the current Az context (Connect-AzAccount).
    API Version    : 2025-07-01
    Author         : Toby G
    Contributors   : @kapetanios55 (Lake Migration Cost Analysis)
    Requires       : Az.Accounts module
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
    [string]$HotRetention,
    [string]$TotalRetention,

    # ── Data Lake ────────────────────────────────────────────────────────────
    [ValidateRange(0, 4383)]
    [Nullable[int]]$DataLakeAgeDays,

    # ── Output ───────────────────────────────────────────────────────────────
    [string]$OutputPath,

    # ── Lake Migration Cost Constants (USD, East US defaults) ────────────────
    # Source: https://learn.microsoft.com/en-us/azure/sentinel/billing
    [ValidateRange(0, 100)]
    [double]$AnalyticsIngestionCostPerGB = 2.30,

    [ValidateRange(0, 100)]
    [double]$LakeIngestionCostPerGB = 0.15,

    [ValidateRange(0, 100)]
    [double]$LakeScanCostPerGB = 0.005,

    # ── Behaviour ────────────────────────────────────────────────────────────
    [int]$ThrottleMs = 200,

    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Now = Get-Date

#region ── Prerequisites ───────────────────────────────────────────────────────

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This script requires PowerShell 7.0 or later (latest stable: 7.5). Current version: $($PSVersionTable.PSVersion). Install from https://aka.ms/powershell"
}

if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
    throw "Az.Accounts module is not installed. Run: Install-Module Az.Accounts -Scope CurrentUser"
}

$azContext = Get-AzContext -ErrorAction SilentlyContinue
if (-not $azContext) {
    throw "No Azure context found. Run Connect-AzAccount before executing this script."
}

Write-Host "  Authenticated as: $($azContext.Account.Id)" -ForegroundColor DarkGray

#endregion

#region ── Helpers ──────────────────────────────────────────────────────────────

$script:AllowedHotRetention = [ordered]@{
    '30d' = 30; '60d' = 60; '90d' = 90; '120d' = 120; '180d' = 180
    '270d' = 270; '1y' = 365; '1.5y' = 547; '2y' = 730; 'default' = -1
}
$script:AllowedTotalRetention = [ordered]@{
    '30d' = 30; '60d' = 60; '90d' = 90; '120d' = 120; '180d' = 180
    '270d' = 270; '1y' = 365; '1.5y' = 547; '2y' = 730; '3y' = 1095
    '4y' = 1460; '5y' = 1826; '6y' = 2191; '7y' = 2556; '8y' = 2922
    '9y' = 3288; '10y' = 3653; '11y' = 4018; '12y' = 4383; 'default' = -1
}

function ConvertTo-RetentionDays {
    param ([string]$Value, [System.Collections.Specialized.OrderedDictionary]$AllowedValues, [string]$ParameterName)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $key = $Value.Trim().ToLower()
    if ($AllowedValues.Contains($key)) { return $AllowedValues[$key] }
    $allowedList = ($AllowedValues.Keys | ForEach-Object {
        $days = $AllowedValues[$_]
        if ($_ -eq 'default') { 'default' } elseif ($days -ge 365) { "$_ ($days days)" } else { $_ }
    }) -join ', '
    throw "-$ParameterName '$Value' is not valid. Allowed: $allowedList"
}

function Format-RetentionFriendly ([int]$Days) {
    $map = @{ -1='-'; 30='30d'; 60='60d'; 90='90d'; 120='120d'; 180='180d'; 270='270d'
              365='1y'; 547='1.5y'; 730='2y'; 1095='3y'; 1460='4y'; 1826='5y'
              2191='6y'; 2556='7y'; 2922='8y'; 3288='9y'; 3653='10y'; 4018='11y'; 4383='12y' }
    $map.ContainsKey($Days) ? $map[$Days] : "${Days}d"
}

function Get-AzBearerToken {
    $context = Get-AzContext
    if (-not $context) { throw "No Az context found. Run Connect-AzAccount first." }
    $tokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"
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
    param ([string]$Uri, [string]$Method = 'GET', [string]$Token, [hashtable]$Body, [int]$Retries = 3)
    $headers = @{ 'Authorization' = "Bearer $Token"; 'Content-Type' = 'application/json' }
    $params = @{ Uri = $Uri; Method = $Method; Headers = $headers }
    if ($Body) { $params['Body'] = ($Body | ConvertTo-Json -Depth 10) }
    $attempt = 0
    while ($true) {
        $attempt++
        try { return Invoke-RestMethod @params }
        catch {
            $resp = $_.Exception.Response
            $statusCode = $resp ? [int]$resp.StatusCode : 0
            $retryable = $statusCode -in @(429, 503, 504)
            if ($retryable -and $attempt -lt $Retries) {
                $waitSec = [Math]::Pow(2, $attempt)
                Write-Warning "  API returned HTTP $statusCode — retrying in ${waitSec}s ($attempt/$Retries)"
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
    $uri = "$BaseUri/tables?api-version=2025-07-01"
    $tables = [System.Collections.Generic.List[object]]::new()
    do {
        $response = Invoke-LAApi -Uri $uri -Method 'GET' -Token $Token -Retries $Retries
        foreach ($t in $response.value) { $tables.Add($t) }
        $uri = ($response.PSObject.Properties['nextLink'] -and $response.nextLink) ? $response.nextLink : $null
    } while ($uri)
    Write-Host " $($tables.Count) tables found" -ForegroundColor Green
    return $tables
}

function Get-SafeProperty ($Obj, [string]$Name, $Default = $null) {
    ($Obj -and $Obj.PSObject.Properties[$Name]) ? $Obj.$Name : $Default
}

function Get-DataAccessWindows {
    param ([int]$CurrentHot, [int]$ProposedHot, [int]$CurrentTotal, [int]$ProposedTotal, [int]$LakeAgeDays)

    $windows = [System.Collections.Generic.List[hashtable]]::new()
    $isReduction = $ProposedHot -lt $CurrentHot

    if ($isReduction) {
        $dualEnd = [Math]::Min($LakeAgeDays, $ProposedHot)
        if ($dualEnd -gt 0) {
            $windows.Add(@{ Start = 0; End = $dualEnd; Where = 'Analytics + Data Lake'; Access = 'Interactive KQL, mirrored to lake'; Class = 'loc-analytics' })
        }
        if ($LakeAgeDays -lt $ProposedHot) {
            $catchUpDays = $ProposedHot - $LakeAgeDays
            $windows.Add(@{ Start = $dualEnd; End = $ProposedHot; Where = 'Analytics only'; Access = "Interactive KQL — lake catches up in ~${catchUpDays}d"; Class = 'loc-analytics' })
        }
        if ($LakeAgeDays -gt $ProposedHot) {
            $lakeEnd = [Math]::Min($LakeAgeDays, $CurrentHot)
            if ($lakeEnd -gt $ProposedHot) {
                $windows.Add(@{ Start = $ProposedHot; End = $lakeEnd; Where = 'Data Lake'; Access = 'KQL jobs / notebooks, no restore'; Class = 'loc-lake' })
            }
        }
        $gapStart = [Math]::Max($ProposedHot, $LakeAgeDays)
        $gapEnd = $CurrentHot
        if ($gapStart -lt $gapEnd) {
            $windows.Add(@{ Start = $gapStart; End = $gapEnd; Where = 'Long-term retention'; Access = 'Search job required (pre-Sentinel Data Lake data)'; Class = 'loc-archive' })
        }
        if ($CurrentHot -lt $ProposedTotal) {
            $ltStart = [Math]::Max($CurrentHot, $gapEnd)
            if ($ltStart -lt $ProposedTotal) {
                $windows.Add(@{ Start = $ltStart; End = $ProposedTotal; Where = 'Long-term retention'; Access = 'Search job required'; Class = 'loc-archive' })
            }
        }
    }
    else {
        $dualEnd = [Math]::Min($LakeAgeDays, $ProposedHot)
        if ($dualEnd -gt 0) {
            $windows.Add(@{ Start = 0; End = $dualEnd; Where = 'Analytics + Data Lake'; Access = 'Interactive KQL, mirrored to lake'; Class = 'loc-analytics' })
        }
        if ($LakeAgeDays -lt $ProposedHot) {
            $catchUpDays = $ProposedHot - $LakeAgeDays
            $windows.Add(@{ Start = $dualEnd; End = $ProposedHot; Where = 'Analytics only'; Access = "Interactive KQL — lake catches up in ~${catchUpDays}d"; Class = 'loc-analytics' })
        }
        if ($ProposedHot -lt $ProposedTotal) {
            $ltStart = $ProposedHot
            $lakeWindow = [Math]::Min($LakeAgeDays, $ProposedTotal) - $ltStart
            if ($lakeWindow -gt 0) {
                $windows.Add(@{
                    Start = $ltStart
                    End = $ltStart + $lakeWindow
                    Where = 'Data Lake'
                    Access = 'KQL jobs / notebooks, no restore'
                    Class = 'loc-lake'
                })
            }
            $searchStart = [Math]::Max($ltStart, $ltStart + $lakeWindow)
            if ($searchStart -lt $ProposedTotal) {
                $windows.Add(@{
                    Start = $searchStart
                    End = $ProposedTotal
                    Where = 'Long-term retention'
                    Access = 'Search job required (pre-Sentinel Data Lake data)'
                    Class = 'loc-archive'
                })
            }
        }
    }
    return $windows
}

function Get-TransitionAdvice {
    param ([int]$CurrentHot, [int]$ProposedHot, [int]$CurrentTotal, [int]$ProposedTotal, [int]$LakeAgeDays)

    $warnings = [System.Collections.Generic.List[hashtable]]::new()
    $recommendations = [System.Collections.Generic.List[hashtable]]::new()
    $isReduction = $ProposedHot -lt $CurrentHot

    if (-not $isReduction) {
        # Not reducing hot, but total retention may still be changing
        $totalChanging = $ProposedTotal -ne $CurrentTotal

        if ($totalChanging -and $ProposedTotal -gt $CurrentTotal) {
            $warnings.Add(@{ Type = 'info'; Text = "Total retention is increasing ($CurrentTotal → $ProposedTotal days). The new period applies immediately to all data already ingested and not yet removed." })
            $longTermDays = $ProposedTotal - $ProposedHot
            if ($longTermDays -gt 0) {
                $warnings.Add(@{ Type = 'info'; Text = "Long-term retention: $longTermDays days of data beyond the ${ProposedHot}-day analytics window will be retained in the data lake / long-term storage." })
            }
        }
        if ($totalChanging -and $ProposedTotal -lt $CurrentTotal) {
            $warnings.Add(@{
                Type = 'success'
                Text = "30-day safety net: reducing total retention ($CurrentTotal → $ProposedTotal days). Azure Monitor waits 30 days before removing data past the new boundary."
            })
        }
        if ($LakeAgeDays -lt $ProposedHot) {
            $daysUntilCoverage = $ProposedHot - $LakeAgeDays
            $coverageDate = $script:Now.AddDays($daysUntilCoverage).ToString('yyyy-MM-dd')
            $warnings.Add(@{
                Type = 'warning'
                Text = "Lake coverage gap: Sentinel Data Lake has $LakeAgeDays days of mirrored data but analytics retention is $ProposedHot days. Full lake coverage in ~$daysUntilCoverage days ($coverageDate)."
            })
        }
        if ($LakeAgeDays -ge $ProposedHot) {
            $recommendations.Add(@{
                Type = 'safe'
                Text = "Sentinel Data Lake has been running for $LakeAgeDays days, fully covering the ${ProposedHot}-day analytics window. All data rolling out of analytics already has a mirrored copy in the lake."
            })
        }
        $warnings.Add(@{ Type = 'info'; Text = "No data loss: data always exists in analytics, data lake, or long-term retention. Only the access method changes." })

        return @{ Warnings = $warnings; Recommendations = $recommendations }
    }

    $daysUntilFullCoverage = [Math]::Max(0, $ProposedHot - $LakeAgeDays)
    $fullCoverageDate = $script:Now.AddDays($daysUntilFullCoverage).ToString('yyyy-MM-dd')

    if ($LakeAgeDays -lt $ProposedHot) {
        $warnings.Add(@{
            Type = 'warning'
            Text = "Interactive gap: Lake has $LakeAgeDays days of mirrored data but analytics retention is $ProposedHot days. Lake will fully cover the rolling window in ~$daysUntilFullCoverage days ($fullCoverageDate)."
        })
    }
    if ($LakeAgeDays -lt $CurrentHot) {
        $archiveStart = [Math]::Max($ProposedHot, $LakeAgeDays)
        $archiveEnd = $CurrentHot
        if ($archiveStart -lt $archiveEnd) {
            $archiveDays = $archiveEnd - $archiveStart
            $warnings.Add(@{
                Type = 'warning'
                Text = "Legacy archive gap: ~$archiveDays days of data (${archiveStart}–${archiveEnd} days old) will only be accessible via restore/search jobs."
            })
        }
    }

    $warnings.Add(@{ Type = 'info'; Text = "No data loss: all data remains accessible in analytics, legacy archive, or data lake. Only the access method changes." })
    $warnings.Add(@{ Type = 'info'; Text = "Legacy archive is static — no new data enters after Sentinel Data Lake onboarding. Existing archive data ages out per totalRetentionInDays." })

    $longTermDays = $ProposedTotal - $ProposedHot
    if ($longTermDays -gt 0) {
        $warnings.Add(@{
            Type = 'info'
            Text = "Auto-reclassification: reducing analytics from $CurrentHot to $ProposedHot days with total at $ProposedTotal days — Azure Monitor treats the remaining $longTermDays days as long-term retention automatically."
        })
    }
    if ($ProposedTotal -lt $CurrentTotal) {
        $warnings.Add(@{
            Type = 'success'
            Text = "30-day safety net: reducing total retention ($CurrentTotal → $ProposedTotal days). Azure Monitor waits 30 days before removing data past the new boundary."
        })
    }

    $safeDaysToWait = [Math]::Max(0, $CurrentHot - $LakeAgeDays)
    $safeDate = $script:Now.AddDays($safeDaysToWait).ToString('yyyy-MM-dd')

    if ($LakeAgeDays -lt $CurrentHot) {
        $recommendations.Add(@{
            Type = 'safest'
            Text = "Wait $safeDaysToWait more days (until $safeDate) before reducing analytics retention. By then the lake will have $CurrentHot days of mirrored data, fully covering the current analytics window."
        })
        $recommendations.Add(@{
            Type = 'acceptable'
            Text = "Apply now if you can tolerate restore-job access for historical data older than $LakeAgeDays days. No data is lost — only the access method changes."
        })
    }
    else {
        $recommendations.Add(@{
            Type = 'safe'
            Text = "Safe to proceed: Sentinel Data Lake has been running for $LakeAgeDays days, which fully covers the current ${CurrentHot}-day analytics window."
        })
    }

    return @{ Warnings = $warnings; Recommendations = $recommendations }
}

function HtmlEncode ([string]$Text) {
    [System.Net.WebUtility]::HtmlEncode($Text)
}

#endregion

#region ── Validation ──────────────────────────────────────────────────────────

$HotRetentionDays   = ConvertTo-RetentionDays -Value $HotRetention   -AllowedValues $script:AllowedHotRetention   -ParameterName 'HotRetention'
$TotalRetentionDays = ConvertTo-RetentionDays -Value $TotalRetention -AllowedValues $script:AllowedTotalRetention -ParameterName 'TotalRetention'

if ($HotRetentionDays -eq -1)   { $HotRetentionDays   = $null }
if ($TotalRetentionDays -eq -1) { $TotalRetentionDays = $null }

if ($null -eq $HotRetentionDays -and $null -eq $TotalRetentionDays) {
    throw "At least one of -HotRetention or -TotalRetention must be specified."
}
if ($null -ne $HotRetentionDays -and $null -ne $TotalRetentionDays) {
    if ($TotalRetentionDays -lt $HotRetentionDays) {
        throw "-TotalRetention ($TotalRetentionDays days) is less than -HotRetention ($HotRetentionDays days)."
    }
}

if (-not $OutputPath) {
    $ts = $script:Now.ToString('yyyyMMdd-HHmmss')
    $OutputPath = Join-Path (Get-Location) "SentinelRetentionReport_${WorkspaceName}_${ts}.html"
}

#endregion

#region ── Data collection ─────────────────────────────────────────────────────

Write-Host "`n  Sentinel Retention Report Generator" -ForegroundColor Cyan
Write-Host "  ===================================`n"
Write-Host "  Workspace : $WorkspaceName"
Write-Host "  Scope     : $(($AllTables ? 'ALL TABLES' : ($TableNames -join ', ')))"

Write-Host "  Acquiring bearer token..." -NoNewline
$token   = Get-AzBearerToken
Write-Host " OK" -ForegroundColor Green

$baseUri = Get-BaseUri -Sub $SubscriptionId -RG $ResourceGroupName -WS $WorkspaceName

if ($AllTables) {
    $allTableObjects = Get-AllWorkspaceTables -BaseUri $baseUri -Token $token -Retries $MaxRetries

    if ($FilterPlan) {
        $allTableObjects = @($allTableObjects | Where-Object { $_.properties.plan -in $FilterPlan })
        Write-Host "  After plan filter  : $($allTableObjects.Count) tables"
    }
    if ($FilterTableType) {
        $allTableObjects = @($allTableObjects | Where-Object { $_.properties.schema.tableType -in $FilterTableType })
        Write-Host "  After type filter  : $($allTableObjects.Count) tables"
    }
    if ($SkipEmpty) {
        Write-Host "  Querying Usage table..." -NoNewline
        $queryUri  = "$baseUri/api/query?api-version=2020-08-01"
        $queryBody = @{ query = "Usage | where TimeGenerated > ago(90d) | distinct DataType" }
        try {
            $queryResp   = Invoke-LAApi -Uri $queryUri -Method 'POST' -Token $token -Body $queryBody -Retries $MaxRetries
            $activeTables = @($queryResp.tables[0].rows | ForEach-Object { $_[0] })
            Write-Host " $($activeTables.Count) active" -ForegroundColor Green
            $allTableObjects = @($allTableObjects | Where-Object { $_.name -in $activeTables })
            Write-Host "  After empty filter : $($allTableObjects.Count) tables"
        }
        catch {
            Write-Warning "  Could not query Usage table: $_ — skipping empty filter"
        }
    }
    $resolvedTableNames = @($allTableObjects | ForEach-Object { $_.name })
} else {
    $allTableObjects    = $null
    $resolvedTableNames = $TableNames
}

$totalTables = @($resolvedTableNames).Count
Write-Host "  Processing         : $totalTables tables`n" -ForegroundColor Cyan

# ── Process each table ────────────────────────────────────────────────────────
$tableData   = [System.Collections.Generic.List[hashtable]]::new()
$changeCount = 0
$skipCount   = 0
$errorCount  = 0
$tableIndex  = 0

foreach ($tableName in $resolvedTableNames) {
    $tableIndex++
    $pct = [int](($tableIndex / [Math]::Max($totalTables, 1)) * 100)
    Write-Progress -Activity "Analysing tables" -Status "$tableIndex / $totalTables — $tableName" -PercentComplete $pct
    Start-Sleep -Milliseconds $ThrottleMs

    if ($allTableObjects) {
        $cachedObj = $allTableObjects | Where-Object { $_.name -eq $tableName } | Select-Object -First 1
        $current = $cachedObj ? $cachedObj.properties : $null
    } else {
        $uri = "$baseUri/tables/${tableName}?api-version=2025-07-01"
        try   { $current = (Invoke-LAApi -Uri $uri -Method 'GET' -Token $token -Retries $MaxRetries).properties }
        catch { $current = $null }
    }

    if (-not $current) {
        $tableData.Add(@{ Table = $tableName; Status = 'error'; Error = 'Not found or inaccessible' })
        $errorCount++
        continue
    }

    $curPlan  = Get-SafeProperty $current 'plan'
    $curType  = $null
    $schema   = Get-SafeProperty $current 'schema'
    if ($schema) { $curType = Get-SafeProperty $schema 'tableType' }
    $curHot   = Get-SafeProperty $current 'retentionInDays' 0
    $curTotal = Get-SafeProperty $current 'totalRetentionInDays' 0
    $curLake  = Get-SafeProperty $current 'archiveRetentionInDays' 0
    $hotDef   = Get-SafeProperty $current 'retentionInDaysAsDefault' $false
    $totalDef = Get-SafeProperty $current 'totalRetentionInDaysAsDefault' $false

    # Compute proposed values
    $effectiveHot = $HotRetentionDays
    $readOnlyHot  = $false
    if ($curPlan -in 'Basic', 'Auxiliary' -and $null -ne $HotRetentionDays) {
        $effectiveHot = $null
        $readOnlyHot  = $true
    }

    $propHot   = ($null -ne $effectiveHot)       ? $effectiveHot       : $curHot
    $propTotal = ($null -ne $TotalRetentionDays) ? $TotalRetentionDays : $curTotal
    $propLake  = ($propHot -gt 0 -and $propTotal -gt 0) ? [Math]::Max(0, $propTotal - $propHot) : $curLake

    $willChange = ($propHot -ne $curHot) -or ($propTotal -ne $curTotal)

    $status = $willChange ? 'change' : 'unchanged'
    if ($willChange) { $changeCount++ } else { $skipCount++ }

    # Data access impact
    $windows = $null
    $advice  = $null
    if ($null -ne $DataLakeAgeDays -and $willChange -and $curPlan -notin 'Basic', 'Auxiliary') {
        $windows = Get-DataAccessWindows -CurrentHot $curHot -ProposedHot $propHot `
            -CurrentTotal $curTotal -ProposedTotal $propTotal -LakeAgeDays $DataLakeAgeDays
        $advice = Get-TransitionAdvice -CurrentHot $curHot -ProposedHot $propHot `
            -CurrentTotal $curTotal -ProposedTotal $propTotal -LakeAgeDays $DataLakeAgeDays
    }

    $tableData.Add(@{
        Table       = $tableName
        Plan        = $curPlan
        TableType   = $curType
        CurHot      = $curHot
        CurTotal    = $curTotal
        CurLake     = $curLake
        HotDefault  = $hotDef
        TotalDefault = $totalDef
        PropHot     = $propHot
        PropTotal   = $propTotal
        PropLake    = $propLake
        Status      = $status
        ReadOnlyHot = $readOnlyHot
        Windows     = $windows
        Advice      = $advice
    })
}

Write-Progress -Activity "Analysing tables" -Completed

# ── Lake Migration Cost Analysis ──────────────────────────────────────────────
$lakeMigrationData = $null
Write-Host "  Running lake migration cost analysis..." -NoNewline
$lakeQuery = @"
// Cost constants injected from script parameters — override with -AnalyticsIngestionCostPerGB, -LakeIngestionCostPerGB, -LakeScanCostPerGB
// Defaults: US East, commitment tier rate. PAYG is 4.30/GB — set -AnalyticsIngestionCostPerGB accordingly
// Source: https://learn.microsoft.com/en-us/azure/sentinel/billing
let analyticsIngestionCost = $AnalyticsIngestionCostPerGB;
let lakeScanCostPerGB = $LakeScanCostPerGB;
let lakeIngestionCostPerGB = $LakeIngestionCostPerGB;
let lookbackDays = 90;
let queryLookbackDays = 7;
let knownTables = toscalar(
    Usage
    | where TimeGenerated > ago(lookbackDays * 1d)
    | summarize make_set(DataType)
);
let avgHourlySizePerTable =
    Usage
    | where TimeGenerated > ago(lookbackDays * 1d)
    | summarize AvgHourlyIngestionGB = avg(Quantity) / 1024 by DataType;
LAQueryLogs
| where TimeGenerated > ago(queryLookbackDays * 1d)
| extend HoursDiff = todouble(datetime_diff('minute', QueryTimeRangeEnd, QueryTimeRangeStart)) / 60
| where isnotempty(HoursDiff) and HoursDiff > 0
| extend QueryOrigin = case(
    RequestClientApp == "Sentinel-DataCollectionAggregator", "Automated"
    , RequestClientApp == "Sentinel-Investigation-Queries", "Automated"
    , RequestClientApp has "sdk" or RequestClientApp has "PSClient", "Automated"
    , RequestClientApp == "AzureMonitorLogsConnector", "Automated"
    , RequestClientApp == "M365D_AdvancedHunting" and isempty(AADEmail), "Automated"
    , "Human")
| serialize QueryNumber = row_number()
| mv-expand TableName = knownTables to typeof(string)
| where QueryText has_cs TableName
| extend ExtractedTables = extract_all(@'(?:^|\|?\s*)([A-Z][A-Za-z0-9_]+)(?:\s*\||\s*$)', QueryText)
| where array_index_of(ExtractedTables, TableName) >= 0
| join kind=leftouter avgHourlySizePerTable on `$left.TableName == `$right.DataType
| extend ScanSizeGB = AvgHourlyIngestionGB * HoursDiff
| summarize
    TotalScannedSizeGB = sum(ScanSizeGB)
    , DistinctQueryCount = dcount(QueryNumber)
    , HumanQueryCount = dcountif(QueryNumber, QueryOrigin == "Human")
    , AutomatedQueryCount = dcountif(QueryNumber, QueryOrigin == "Automated")
    , AvgHourlyIngestionGB = avg(AvgHourlyIngestionGB)
    by DataType
| extend
    ProjectedWeeklyKQLLakeCost = TotalScannedSizeGB * lakeScanCostPerGB
    , AnalyticsWeeklyCost = AvgHourlyIngestionGB * analyticsIngestionCost * 24 * 7
    , LakeIngestionWeeklyCost = AvgHourlyIngestionGB * lakeIngestionCostPerGB * 24 * 7
| extend
    CostDelta = AnalyticsWeeklyCost - (ProjectedWeeklyKQLLakeCost + LakeIngestionWeeklyCost)
    , CandidateForLakeOnly = iif(
        AnalyticsWeeklyCost > ProjectedWeeklyKQLLakeCost + LakeIngestionWeeklyCost
        , "Move to Lake"
        , "Keep in Analytics")
| project
    DataType
    , AvgHourlyIngestionGB
    , TotalScannedSizeGB
    , DistinctQueryCount
    , HumanQueryCount
    , AutomatedQueryCount
    , AnalyticsWeeklyCost
    , ProjectedWeeklyKQLLakeCost
    , LakeIngestionWeeklyCost
    , CostDelta
    , CandidateForLakeOnly
| sort by CostDelta desc
"@
try {
    $lakeQueryUri  = "$baseUri/api/query?api-version=2020-08-01"
    $lakeQueryBody = @{ query = $lakeQuery }
    $lakeQueryResp = Invoke-LAApi -Uri $lakeQueryUri -Method 'POST' -Token $token -Body $lakeQueryBody -Retries $MaxRetries
    $lakeColumns   = $lakeQueryResp.tables[0].columns
    $lakeRows      = $lakeQueryResp.tables[0].rows
    $lakeMigrationData = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($row in $lakeRows) {
        $entry = @{}
        for ($i = 0; $i -lt $lakeColumns.Count; $i++) {
            $colName = $lakeColumns[$i].ColumnName
            if (-not $colName) { $colName = $lakeColumns[$i].name }
            $entry[$colName] = $row[$i]
        }
        $lakeMigrationData.Add($entry)
    }
    Write-Host " $($lakeMigrationData.Count) tables analysed" -ForegroundColor Green
}
catch {
    Write-Warning "  Could not run lake migration query: $_ — skipping cost analysis"
    $lakeMigrationData = $null
}

#endregion


#region ── Build HTML report ───────────────────────────────────────────────────

Write-Host "  Generating HTML report..." -NoNewline

$reportDate     = $script:Now.ToString('dd MMM yyyy HH:mm:ss')
$hotLabel       = ($null -ne $HotRetentionDays) ? (Format-RetentionFriendly $HotRetentionDays) : '(unchanged)'
$totalLabel     = ($null -ne $TotalRetentionDays) ? (Format-RetentionFriendly $TotalRetentionDays) : '(unchanged)'
$sdlLabel       = ($null -ne $DataLakeAgeDays) ? "$DataLakeAgeDays days" : 'Not specified'
$unchangedCount = @($tableData | Where-Object { $_.Status -eq 'unchanged' }).Count

# ── Helper: build table rows HTML ─────────────────────────────────────────────
function Build-TableRowsHtml {
    param ([System.Collections.Generic.List[hashtable]]$Tables)
    $sb = [System.Text.StringBuilder]::new()
    foreach ($t in $Tables) {
        if ($t.Status -eq 'error') {
            [void]$sb.AppendLine("        <tr class=`"row-error`"><td>$(HtmlEncode $t.Table)</td><td colspan=`"6`" class=`"error-cell`">$($t.Error)</td></tr>")
            continue
        }
        $rowClass = $t.Status -eq 'change' ? 'row-change' : 'row-unchanged'
        $badge    = $t.Status -eq 'change' ? '<span class="badge badge-change">WILL CHANGE</span>' : '<span class="badge badge-ok">NO CHANGE</span>'
        $hotArrow   = ($t.CurHot -ne $t.PropHot)    ? "$(Format-RetentionFriendly $t.CurHot) &rarr; <strong>$(Format-RetentionFriendly $t.PropHot)</strong>" : (Format-RetentionFriendly $t.CurHot)
        $totalArrow = ($t.CurTotal -ne $t.PropTotal) ? "$(Format-RetentionFriendly $t.CurTotal) &rarr; <strong>$(Format-RetentionFriendly $t.PropTotal)</strong>" : (Format-RetentionFriendly $t.CurTotal)
        $lakeVal    = ($t.PropLake -ge 0) ? "$($t.PropLake)d" : '—'
        $hotDef   = [bool]$t.HotDefault ? ' <span class="tag-default">ws-default</span>' : ''
        $totalDef = [bool]$t.TotalDefault ? ' <span class="tag-default">ws-default</span>' : ''
        $hasImpact  = $t.Windows -and $t.Windows.Count -gt 0
        $toggleAttr = $hasImpact ? ' class="toggle-row" style="cursor:pointer"' : ''
        $toggleIcon = $hasImpact ? '<span class="toggle-icon">&#x25B6;</span> ' : ''

        [void]$sb.AppendLine("        <tr class=`"$rowClass`" data-plan=`"$($t.Plan)`"$toggleAttr>")
        [void]$sb.AppendLine("          <td class=`"table-name`">$toggleIcon$(HtmlEncode $t.Table)</td>")
        [void]$sb.AppendLine("          <td><span class=`"plan-badge plan-$($t.Plan?.ToLower())`">$($t.Plan)</span></td>")
        [void]$sb.AppendLine("          <td>$($t.TableType)</td><td>$hotArrow$hotDef</td>")
        [void]$sb.AppendLine("          <td>$totalArrow$totalDef</td><td>$lakeVal</td><td>$badge</td></tr>")

        if ($hasImpact) {
            $imp = [System.Text.StringBuilder]::new()
            [void]$imp.Append('<table class="impact-table"><thead><tr><th>Time Window</th><th>Data Location</th><th>Access Method</th></tr></thead><tbody>')
            foreach ($w in $t.Windows) {
                [void]$imp.Append("<tr class=`"$($w.Class)`"><td class=`"impact-window`">$($w.Start)–$($w.End)d ago</td><td class=`"impact-where`">$($w.Where)</td><td class=`"impact-access`">$($w.Access)</td></tr>")
            }
            [void]$imp.Append('</tbody></table>')
            if ($t.Advice) {
                if ($t.Advice.Warnings.Count -gt 0) {
                    [void]$imp.Append('<div class="advice-section">')
                    foreach ($warn in $t.Advice.Warnings) {
                        $ic = ($warn.Type -eq 'warning') ? 'adv-warning' : (($warn.Type -eq 'success') ? 'adv-success' : 'adv-info')
                        [void]$imp.Append("<div class=`"advice-item $ic`">$(HtmlEncode $warn.Text)</div>")
                    }
                    [void]$imp.Append('</div>')
                }
                if ($t.Advice.Recommendations.Count -gt 0) {
                    [void]$imp.Append('<div class="rec-section"><div class="rec-heading">Recommendations</div>')
                    foreach ($rec in $t.Advice.Recommendations) {
                        $rc = ($rec.Type -eq 'safest') ? 'rec-safest' : (($rec.Type -eq 'safe') ? 'rec-safe' : 'rec-acceptable')
                        [void]$imp.Append("<div class=`"rec-item $rc`">$(HtmlEncode $rec.Text)</div>")
                    }
                    [void]$imp.Append('</div>')
                }
            }
            [void]$sb.AppendLine("        <tr class=`"detail-row`" style=`"display:none`"><td colspan=`"7`"><div class=`"impact-detail`">$($imp.ToString())</div></td></tr>")
        }
    }
    return $sb.ToString()
}

# ── Split tables ──────────────────────────────────────────────────────────────
$changedTables   = [System.Collections.Generic.List[hashtable]]::new()
$unchangedTables = [System.Collections.Generic.List[hashtable]]::new()
foreach ($t in ($tableData | Sort-Object { $_.Table } -Culture 'en-US')) {
    if ($t.Status -eq 'change' -or $t.Status -eq 'error') { $changedTables.Add($t) }
    else { $unchangedTables.Add($t) }
}
$changeRowsHtml    = Build-TableRowsHtml $changedTables
$unchangedRowsHtml = Build-TableRowsHtml $unchangedTables

# ── Aggregate recommendations & warnings ──────────────────────────────────────
$recWarningsHtml = [System.Text.StringBuilder]::new()
$seenRecs  = [ordered]@{}
$seenWarns = [ordered]@{}
foreach ($t in $tableData) {
    if (-not $t.Advice) { continue }
    foreach ($r in $t.Advice.Recommendations) { if (-not $seenRecs.Contains($r.Text))  { $seenRecs[$r.Text]  = $r } }
    foreach ($w in $t.Advice.Warnings)        { if (-not $seenWarns.Contains($w.Text))  { $seenWarns[$w.Text]  = $w } }
}
if ($seenRecs.Count -gt 0) {
    [void]$recWarningsHtml.Append('<h3>Recommendations</h3>')
    foreach ($r in $seenRecs.Values) {
        $rc = ($r.Type -eq 'safest') ? 'rec-safest' : (($r.Type -eq 'safe') ? 'rec-safe' : 'rec-acceptable')
        [void]$recWarningsHtml.Append("<div class=`"rec-item $rc`">$(HtmlEncode $r.Text)</div>")
    }
}
if ($seenWarns.Count -gt 0) {
    [void]$recWarningsHtml.Append('<h3 style="margin-top:20px">Warnings &amp; Notes</h3>')
    foreach ($w in $seenWarns.Values) {
        $ic = ($w.Type -eq 'warning') ? 'adv-warning' : (($w.Type -eq 'success') ? 'adv-success' : 'adv-info')
        [void]$recWarningsHtml.Append("<div class=`"advice-item $ic`">$(HtmlEncode $w.Text)</div>")
    }
}
if ($seenRecs.Count -eq 0 -and $seenWarns.Count -eq 0) {
    [void]$recWarningsHtml.Append('<p class="muted">No recommendations — Sentinel Data Lake age not specified or no changes detected.</p>')
}
$recWarnCount = $seenRecs.Count + $seenWarns.Count

# ── Lake Migration HTML ──────────────────────────────────────────────────────
$lakeMigrationHtml = ''
$lakeMigrationCount = 0
$lakeMoveCandidates = 0
if ($lakeMigrationData -and $lakeMigrationData.Count -gt 0) {
    $lakeMigrationCount = $lakeMigrationData.Count
    $lakeMoveCandidates = @($lakeMigrationData | Where-Object { $_.CandidateForLakeOnly -eq 'Move to Lake' }).Count
    $totalSavings = ($lakeMigrationData | Where-Object { $_.CostDelta -gt 0 } | ForEach-Object { $_.CostDelta } | Measure-Object -Sum).Sum
    $totalSavingsStr = '{0:N2}' -f $totalSavings

    $lmSb = [System.Text.StringBuilder]::new()
    [void]$lmSb.AppendLine('<div class="summary-row" style="margin-bottom:20px">')
    [void]$lmSb.AppendLine("  <div class=`"summary-card sc-total`"><div class=`"num`">$lakeMigrationCount</div><div class=`"label`">Tables Analysed</div></div>")
    [void]$lmSb.AppendLine("  <div class=`"summary-card sc-change`"><div class=`"num`">$lakeMoveCandidates</div><div class=`"label`">Move to Lake</div></div>")
    [void]$lmSb.AppendLine("  <div class=`"summary-card sc-ok`"><div class=`"num`">$($lakeMigrationCount - $lakeMoveCandidates)</div><div class=`"label`">Keep in Analytics</div></div>")
    [void]$lmSb.AppendLine("  <div class=`"summary-card`" style=`"border-color:var(--green)`"><div class=`"num`" style=`"color:var(--green)`">`$$totalSavingsStr</div><div class=`"label`">Potential Weekly Savings</div></div>")
    [void]$lmSb.AppendLine('</div>')

    [void]$lmSb.AppendLine('<p class="muted" style="margin-bottom:16px">Cost analysis based on <strong>90-day</strong> average ingestion and <strong>7-day</strong> query volume from LAQueryLogs. Tables where Data Lake ingestion + scan cost is lower than Analytics cost are candidates for migration. Pricing: Analytics `$$("{0:N2}" -f $AnalyticsIngestionCostPerGB)/GB, Lake ingestion `$$("{0:N2}" -f $LakeIngestionCostPerGB)/GB, Lake scan `$$("{0:N3}" -f $LakeScanCostPerGB)/GB.</p>')

    [void]$lmSb.AppendLine('<div class="table-controls"><div class="control-group"><label>Search</label><input type="text" class="tbl-search" placeholder="Filter by table name..."></div>')
    [void]$lmSb.AppendLine('<div class="control-group"><label>Recommendation</label><select class="tbl-plan-filter"><option value="all">All</option><option value="Move to Lake">Move to Lake</option><option value="Keep in Analytics">Keep in Analytics</option></select></div></div>')

    [void]$lmSb.AppendLine('<div class="table-wrap"><table class="main-table"><thead><tr>')
    [void]$lmSb.AppendLine('<th data-col="0">Table</th><th data-col="1">Avg Hourly Ingestion (GB)</th><th data-col="2">Scanned (GB/wk)</th>')
    [void]$lmSb.AppendLine('<th data-col="3">Queries</th><th data-col="4">Human</th><th data-col="5">Automated</th>')
    [void]$lmSb.AppendLine('<th data-col="6">Analytics $/wk</th><th data-col="7">Lake Scan $/wk</th><th data-col="8">Lake Ingestion $/wk</th>')
    [void]$lmSb.AppendLine('<th data-col="9">Savings $/wk</th><th data-col="10">Recommendation</th>')
    [void]$lmSb.AppendLine('</tr></thead><tbody>')

    try {
        foreach ($row in $lakeMigrationData) {
            $isMove = $row.CandidateForLakeOnly -eq 'Move to Lake'
            $rowCls = $isMove ? 'row-change' : ''
            $badge  = $isMove ? '<span class="badge badge-change">MOVE TO LAKE</span>' : '<span class="badge badge-ok">KEEP IN ANALYTICS</span>'
            $costDelta  = [double]($row.CostDelta ?? 0)
            $deltaSign  = ($costDelta -gt 0) ? '+' : ''
            $deltaColor = ($costDelta -gt 0) ? 'color:var(--green);font-weight:700' : 'color:var(--text-secondary)'

            [void]$lmSb.AppendLine("  <tr class=`"$rowCls`" data-plan=`"$(HtmlEncode $row.CandidateForLakeOnly)`">")
            [void]$lmSb.AppendLine("    <td class=`"table-name`">$(HtmlEncode $row.DataType)</td>")
            [void]$lmSb.AppendLine("    <td>$('{0:N4}' -f [double]($row.AvgHourlyIngestionGB ?? 0))</td>")
            [void]$lmSb.AppendLine("    <td>$('{0:N2}' -f [double]($row.TotalScannedSizeGB ?? 0))</td>")
            [void]$lmSb.AppendLine("    <td>$($row.DistinctQueryCount ?? 0)</td>")
            [void]$lmSb.AppendLine("    <td>$($row.HumanQueryCount ?? 0)</td>")
            [void]$lmSb.AppendLine("    <td>$($row.AutomatedQueryCount ?? 0)</td>")
            [void]$lmSb.AppendLine("    <td>`$$('{0:N2}' -f [double]($row.AnalyticsWeeklyCost ?? 0))</td>")
            [void]$lmSb.AppendLine("    <td>`$$('{0:N2}' -f [double]($row.ProjectedWeeklyKQLLakeCost ?? 0))</td>")
            [void]$lmSb.AppendLine("    <td>`$$('{0:N2}' -f [double]($row.LakeIngestionWeeklyCost ?? 0))</td>")
            [void]$lmSb.AppendLine("    <td style=`"$deltaColor`">$deltaSign`$$('{0:N2}' -f $costDelta)</td>")
            [void]$lmSb.AppendLine("    <td>$badge</td>")
            [void]$lmSb.AppendLine("  </tr>")
        }
    }
    catch {
        Write-Warning "  Error rendering lake migration row: $_"
        [void]$lmSb.AppendLine('<tr><td colspan="11" class="error-cell">Error rendering row data</td></tr>')
    }

    [void]$lmSb.AppendLine('</tbody></table></div>')
    $lakeMigrationHtml = $lmSb.ToString()
} else {
    $lakeMigrationHtml = '<p class="muted">Lake migration cost analysis could not be performed. Ensure LAQueryLogs is enabled in the workspace.</p>'
}

# ── Sentinel Data Lake summary ───────────────────────────────────────────────────────────────
$sdlHtml = ''
if ($null -ne $DataLakeAgeDays) {
    $sdlHtml = @"
      <div class="facts-grid facts-3col">
        <div class="fact-card fact-green">
          <div class="fact-icon">&#x2714;</div>
          <div class="fact-text"><strong>No data loss</strong> when reducing analytics retention. Azure Monitor automatically treats the difference as long-term retention. Data is reclassified, not deleted.<div class="fact-link"><a href="https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-retention-configure" target="_blank" rel="noopener">Learn more &rarr;</a></div></div>
        </div>
        <div class="fact-card">
          <div class="fact-icon">&#x1F6E1;</div>
          <div class="fact-text"><strong>30-day safety net</strong> — when you shorten total retention, Azure Monitor waits 30 days before removing data past the new boundary. You can revert within that window.<div class="fact-link"><a href="https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-retention-configure" target="_blank" rel="noopener">Learn more &rarr;</a></div></div>
        </div>
        <div class="fact-card">
          <div class="fact-icon">&#x27A1;</div>
          <div class="fact-text"><strong>Mirroring is automatic</strong> — analytics tier data is mirrored to the data lake at ingestion, preserving a single copy. Mirroring is forward-only; pre-SDL data is not retroactively migrated.<div class="fact-link"><a href="https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-lake-connectors" target="_blank" rel="noopener">Learn more &rarr;</a></div></div>
        </div>
        <div class="fact-card">
          <div class="fact-icon">&#x1F4B0;</div>
          <div class="fact-text"><strong>31-day cost floor</strong> — 31 days of analytics retention are included in the ingestion price. Setting analytics retention below 31 days does not reduce costs.<div class="fact-link"><a href="https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-retention-configure" target="_blank" rel="noopener">Learn more &rarr;</a></div></div>
        </div>
        <div class="fact-card">
          <div class="fact-icon">&#x1F4BE;</div>
          <div class="fact-text"><strong>6:1 storage compression</strong> — data lake storage is billed at a fixed 6:1 compression rate (600 GB raw = 100 GB billed). This discount applies to storage only — query charges use uncompressed size.<div class="fact-link"><a href="https://learn.microsoft.com/en-us/azure/sentinel/billing" target="_blank" rel="noopener">Learn more &rarr;</a></div></div>
        </div>
        <div class="fact-card">
          <div class="fact-icon">&#x1F4CB;</div>
          <div class="fact-text"><strong>Free mirroring</strong> — mirrored data from the analytics tier to the data lake incurs no additional ingestion or storage cost during the analytics retention window. Lake storage charges begin when data ages past analytics retention.<div class="fact-link"><a href="https://learn.microsoft.com/en-us/azure/sentinel/manage-data-overview" target="_blank" rel="noopener">Learn more &rarr;</a></div></div>
        </div>
        <div class="fact-card">
          <div class="fact-icon">&#x1F50D;</div>
          <div class="fact-text"><strong>Search jobs for long-term data</strong> — data beyond analytics retention that isn't in the lake requires a search job to retrieve into a search results table. Search jobs are billed per GB of data scanned.<div class="fact-link"><a href="https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-retention-configure" target="_blank" rel="noopener">Learn more &rarr;</a></div></div>
        </div>
        <div class="fact-card">
          <div class="fact-icon">&#x1F4CA;</div>
          <div class="fact-text"><strong>Lake query charges</strong> — KQL jobs and Jupyter notebooks against data lake data are billed per GB of uncompressed data analysed. The 6:1 compression discount does not apply to query costs.<div class="fact-link"><a href="https://learn.microsoft.com/en-us/azure/sentinel/billing" target="_blank" rel="noopener">Learn more &rarr;</a></div></div>
        </div>
        <div class="fact-card">
          <div class="fact-icon">&#x1F4C2;</div>
          <div class="fact-text"><strong>Single copy of data</strong> — the data lake stores one copy of your security data in open-format Parquet files. Analytics and lake tiers share this copy, avoiding duplication and enabling KQL, Python, and ML analytics over the same dataset.<div class="fact-link"><a href="https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-lake-overview" target="_blank" rel="noopener">Learn more &rarr;</a></div></div>
        </div>
      </div>
      <h3>Access Methods by Data Tier</h3>
      <table class="access-table">
        <thead><tr><th>Tier</th><th>Access Method</th><th>Characteristics</th></tr></thead>
        <tbody>
          <tr class="loc-analytics"><td>Analytics (hot)</td><td>Interactive KQL, analytics rules, threat hunting</td><td>No per-query cost, up to 2 years</td></tr>
          <tr class="loc-lake"><td>Data Lake</td><td>KQL jobs, Jupyter notebooks</td><td>No restore needed, up to 12 years</td></tr>
          <tr class="loc-archive"><td>Long-term retention</td><td>Search jobs</td><td>Per-GB query cost, not real-time</td></tr>
        </tbody>
      </table>
"@
} else {
    $sdlHtml = '<p class="muted">Provide <code>-DataLakeAgeDays</code> to see the Sentinel Data Lake transition analysis.</p>'
}

# ── Table template ────────────────────────────────────────────────────────────
$tableTemplate = @"
    <div class="table-controls">
      <div class="control-group"><label>Search</label><input type="text" class="tbl-search" placeholder="Filter by table name…"></div>
      <div class="control-group"><label>Plan</label>
        <select class="tbl-plan-filter"><option value="all">All</option><option value="Analytics">Analytics</option><option value="Basic">Basic</option><option value="Auxiliary">Auxiliary</option></select>
      </div>
      <button class="expand-btn tbl-expand">Expand all</button>
    </div>
    <div class="table-wrap"><table class="main-table">
      <thead><tr><th data-col="0">Table</th><th data-col="1">Plan</th><th data-col="2">Type</th><th data-col="3">Hot Retention</th><th data-col="4">Total Retention</th><th data-col="5">Lake / Archive</th><th data-col="6">Status</th></tr></thead>
      <tbody>%%ROWS%%</tbody>
    </table></div>
"@
$changeTableHtml    = $tableTemplate -replace '%%ROWS%%', $changeRowsHtml
$unchangedTableHtml = $tableTemplate -replace '%%ROWS%%', $unchangedRowsHtml

# ── Assemble HTML ─────────────────────────────────────────────────────────────
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel Retention Report — $WorkspaceName</title>
<style>
:root{--bg:#fff;--bg-alt:#f8f9fb;--bg-card:#fff;--border:#e2e5ea;--border-light:#eef0f3;--text:#1a1d23;--text-secondary:#5f6878;--text-muted:#8b95a5;--accent:#2563eb;--accent-light:#eff4ff;--green:#16a34a;--green-bg:#f0fdf4;--green-border:#bbf7d0;--amber:#d97706;--amber-bg:#fffbeb;--amber-border:#fde68a;--red:#dc2626;--red-bg:#fef2f2;--blue-bg:#eff6ff;--blue-border:#bfdbfe;--teal:#0d9488;--teal-bg:#f0fdfa}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,system-ui,sans-serif;background:var(--bg-alt);color:var(--text);line-height:1.5;-webkit-font-smoothing:antialiased}
.rc{max-width:1400px;margin:0 auto;padding:32px 24px}
.report-header{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:32px;margin-bottom:24px}
.report-header h1{font-size:1.5rem;font-weight:700;letter-spacing:-.02em;margin-bottom:4px}
.report-header .subtitle{color:var(--text-secondary);font-size:.875rem;margin-bottom:20px}
.meta-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.meta-item{background:var(--bg-alt);border-radius:8px;padding:12px 16px}
.meta-label{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin-bottom:2px}
.meta-value{font-size:.95rem;font-weight:600}
.summary-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}
.summary-card{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:20px;text-align:center}
.summary-card .num{font-size:2rem;font-weight:700;line-height:1;margin-bottom:4px}
.summary-card .label{font-size:.75rem;font-weight:500;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.04em}
.sc-change .num{color:var(--amber)}.sc-ok .num{color:var(--green)}.sc-error .num{color:var(--red)}.sc-total .num{color:var(--accent)}
.tab-bar{display:flex;gap:0;border-bottom:2px solid var(--border);background:var(--bg-card);border-radius:12px 12px 0 0;padding:0 8px;overflow-x:auto}
.tab-btn{padding:14px 22px;font-size:.85rem;font-weight:600;color:var(--text-secondary);background:none;border:none;border-bottom:3px solid transparent;cursor:pointer;white-space:nowrap;transition:all .15s}
.tab-btn:hover{color:var(--text);background:var(--bg-alt)}
.tab-btn.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-count{display:inline-block;margin-left:6px;padding:1px 7px;border-radius:10px;font-size:.7rem;font-weight:700;background:var(--bg-alt);color:var(--text-muted)}
.tab-btn.active .tab-count{background:var(--accent-light);color:var(--accent)}
.tab-panel{display:none;background:var(--bg-card);border:1px solid var(--border);border-top:none;border-radius:0 0 12px 12px;padding:28px 32px;margin-bottom:24px}
.tab-panel.active{display:block}
.tab-panel h2{font-size:1.1rem;font-weight:700;margin-bottom:16px}
.tab-panel h3{font-size:.9rem;font-weight:700;margin:20px 0 10px}
.table-controls{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:16px;padding:12px 0}
.control-group{display:flex;align-items:center;gap:6px}
.table-controls label{font-size:.8rem;font-weight:600;color:var(--text-secondary)}
.table-controls input[type="text"]{padding:6px 12px;border:1px solid var(--border);border-radius:6px;font-size:.85rem;width:220px;outline:none}
.table-controls input:focus{border-color:var(--accent)}
.table-controls select{padding:6px 10px;border:1px solid var(--border);border-radius:6px;font-size:.85rem;background:var(--bg);cursor:pointer}
.expand-btn{margin-left:auto;padding:6px 14px;background:var(--bg-alt);border:1px solid var(--border);border-radius:6px;font-size:.8rem;font-weight:600;cursor:pointer;color:var(--text-secondary)}
.expand-btn:hover{background:var(--border-light)}
.table-wrap{border:1px solid var(--border);border-radius:10px;overflow:auto;max-height:80vh}
table.main-table{width:100%;border-collapse:collapse;font-size:.85rem}
table.main-table thead th{background:var(--bg-alt);padding:10px 14px;text-align:left;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:var(--text-secondary);border-bottom:2px solid var(--border);position:sticky;top:0;cursor:pointer;user-select:none;white-space:nowrap}
table.main-table thead th:hover{color:var(--accent)}
table.main-table tbody td{padding:10px 14px;border-bottom:1px solid var(--border-light);vertical-align:top}
table.main-table tbody tr:last-child td{border-bottom:none}
.table-name{font-weight:600;font-family:'Cascadia Code','SF Mono','Consolas',monospace;font-size:.82rem}
.row-change{background:var(--amber-bg)}.row-error{background:var(--red-bg)}.error-cell{color:var(--red);font-weight:500}
tr.hidden-row{display:none}
.toggle-row:hover{background:var(--border-light)}
.toggle-icon{display:inline-block;font-size:.65rem;margin-right:4px;transition:transform .15s;color:var(--text-muted)}
.toggle-row.open .toggle-icon{transform:rotate(90deg)}
.detail-row td{padding:0 14px 14px;background:var(--bg-alt);border-bottom:2px solid var(--border)}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:700;letter-spacing:.03em;text-transform:uppercase}
.badge-change{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-border)}
.badge-ok{background:var(--green-bg);color:var(--green);border:1px solid var(--green-border)}
.tag-default{display:inline-block;padding:1px 5px;border-radius:3px;font-size:.65rem;font-weight:600;background:var(--blue-bg);color:var(--accent);border:1px solid var(--blue-border)}
.plan-badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:.72rem;font-weight:600}
.plan-analytics{background:var(--blue-bg);color:var(--accent)}.plan-basic{background:var(--teal-bg);color:var(--teal)}.plan-auxiliary{background:var(--bg-alt);color:var(--text-secondary)}
.impact-detail{font-size:.82rem;line-height:1.6;padding-top:12px}
table.impact-table{width:100%;border-collapse:collapse;font-size:.82rem;margin-bottom:8px}
table.impact-table thead th{text-align:left;padding:6px 12px;background:var(--bg-card);font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--text-muted);border-bottom:1px solid var(--border)}
table.impact-table td{padding:8px 12px;border-bottom:1px solid var(--border-light);vertical-align:top}
table.impact-table tr:last-child td{border-bottom:none}
.impact-window{font-family:'Cascadia Code','SF Mono','Consolas',monospace;font-weight:600;font-size:.78rem;white-space:nowrap}
.impact-where{font-weight:600;white-space:nowrap}.impact-access{color:var(--text-secondary)}
table.impact-table tr.loc-analytics .impact-where{color:var(--green)}
table.impact-table tr.loc-lake .impact-where{color:var(--accent)}
table.impact-table tr.loc-archive .impact-where{color:var(--amber)}
.advice-section,.rec-section{margin-top:10px}
.rec-heading{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--text-secondary);margin-bottom:4px}
.advice-item,.rec-item{margin-top:6px;padding:8px 12px;border-radius:6px;font-size:.82rem;line-height:1.45}
.adv-warning{background:var(--amber-bg);border-left:3px solid var(--amber)}
.adv-info{background:var(--blue-bg);border-left:3px solid var(--accent)}
.adv-success{background:var(--green-bg);border-left:3px solid var(--green)}
.rec-safest,.rec-safe{background:var(--green-bg);border-left:3px solid var(--green);font-weight:500}
.rec-acceptable{background:var(--amber-bg);border-left:3px solid var(--amber)}
.muted{color:var(--text-muted);font-size:.82rem}
.facts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-bottom:20px}
.facts-3col{grid-template-columns:repeat(3,1fr)}
.fact-card{background:var(--bg-alt);border-radius:8px;padding:16px;display:flex;gap:12px;align-items:flex-start}
.fact-green{background:var(--green-bg)}.fact-icon{font-size:1.2rem;flex-shrink:0;margin-top:1px}.fact-text{font-size:.82rem;line-height:1.5}
.fact-link{margin-top:6px}
.fact-link a{font-size:.75rem;font-weight:600;color:var(--accent);text-decoration:none}
.fact-link a:hover{text-decoration:underline}
table.access-table{width:100%;border-collapse:collapse;font-size:.82rem}
table.access-table th{text-align:left;padding:8px 14px;background:var(--bg-alt);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--text-secondary);border-bottom:2px solid var(--border)}
table.access-table td{padding:8px 14px;border-bottom:1px solid var(--border-light)}
table.access-table .loc-analytics td:first-child{color:var(--green);font-weight:600}
table.access-table .loc-lake td:first-child{color:var(--accent);font-weight:600}
table.access-table .loc-archive td:first-child{color:var(--amber);font-weight:600}
.refs-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px;margin-top:8px}
.refs-3col{grid-template-columns:repeat(3,1fr)}
.ref-card{display:block;background:var(--bg-alt);border:1px solid var(--border);border-radius:8px;padding:16px;text-decoration:none;color:var(--text);transition:border-color .15s,box-shadow .15s}
.ref-card:hover{border-color:var(--accent);box-shadow:0 2px 8px rgba(37,99,235,.1)}
.ref-title{font-size:.85rem;font-weight:600;color:var(--accent);margin-bottom:4px}
.ref-desc{font-size:.78rem;color:var(--text-secondary);line-height:1.45}
.report-footer{text-align:center;padding:20px;font-size:.75rem;color:var(--text-muted)}
.report-footer a{color:var(--accent);text-decoration:none}
@media print{body{background:#fff}.tab-bar{display:none}.tab-panel{display:block!important;border:none}.table-controls{display:none}.rc{padding:0}}
</style>
</head>
<body>
<div class="rc">
  <header class="report-header">
    <h1>Sentinel Retention Assessment Report</h1>
    <p class="subtitle">Read-only analysis — no changes were made to the workspace</p>
    <div class="meta-grid">
      <div class="meta-item"><div class="meta-label">Workspace</div><div class="meta-value">$(HtmlEncode $WorkspaceName)</div></div>
      <div class="meta-item"><div class="meta-label">Resource Group</div><div class="meta-value">$(HtmlEncode $ResourceGroupName)</div></div>
      <div class="meta-item"><div class="meta-label">Subscription</div><div class="meta-value" style="font-size:.78rem">$SubscriptionId</div></div>
      <div class="meta-item"><div class="meta-label">Proposed Hot</div><div class="meta-value">$hotLabel</div></div>
      <div class="meta-item"><div class="meta-label">Proposed Total</div><div class="meta-value">$totalLabel</div></div>
      <div class="meta-item"><div class="meta-label">Sentinel Data Lake Age</div><div class="meta-value">$sdlLabel</div></div>
      <div class="meta-item"><div class="meta-label">Generated</div><div class="meta-value">$reportDate</div></div>
      <div class="meta-item"><div class="meta-label">API Version</div><div class="meta-value">2025-07-01</div></div>
    </div>
  </header>
  <div class="summary-row">
    <div class="summary-card sc-total"><div class="num">$totalTables</div><div class="label">Tables Analysed</div></div>
    <div class="summary-card sc-change"><div class="num">$changeCount</div><div class="label">Would Change</div></div>
    <div class="summary-card sc-ok"><div class="num">$unchangedCount</div><div class="label">Already Correct</div></div>
    <div class="summary-card sc-error"><div class="num">$errorCount</div><div class="label">Errors</div></div>
  </div>
  <div class="tab-bar">
    <button class="tab-btn active" data-tab="summary">Summary &amp; Sentinel Data Lake Overview</button>
    <button class="tab-btn" data-tab="refs">Microsoft Docs</button>
    <button class="tab-btn" data-tab="recs">Recommendations<span class="tab-count">$recWarnCount</span></button>
    <button class="tab-btn" data-tab="changes">Will Change<span class="tab-count">$changeCount</span></button>
    <button class="tab-btn" data-tab="unchanged">No Change<span class="tab-count">$unchangedCount</span></button>
    <button class="tab-btn" data-tab="lakemigration">Lake Migration<span class="tab-count">$lakeMigrationCount</span></button>
  </div>
  <div class="tab-panel active" id="tab-summary">
    <h2>Sentinel Data Lake Transition Overview</h2>
    <p class="muted" style="margin-bottom:20px">Sentinel Data Lake has been running for <strong>$sdlLabel</strong>.</p>
    $sdlHtml
  </div>
  <div class="tab-panel" id="tab-refs">
    <h2>Microsoft Documentation References</h2>
    <div class="refs-grid refs-3col">
      <a class="ref-card" href="https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-retention-configure" target="_blank" rel="noopener"><div class="ref-title">Manage data retention in a Log Analytics workspace</div><div class="ref-desc">Configure analytics and total retention at workspace and table level. Covers how retention modifications work — the 30-day safety net when shortening total retention, auto-reclassification of analytics to long-term retention, the 31-day cost floor, and PATCH vs PUT API behaviour.</div></a>
      <a class="ref-card" href="https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-lake-overview" target="_blank" rel="noopener"><div class="ref-title">Microsoft Sentinel data lake overview</div><div class="ref-desc">Purpose-built cloud-native security data lake architecture. Covers the two storage tiers (analytics and data lake), automatic mirroring from analytics to lake, open-format Parquet storage, separation of storage and compute, KQL jobs, Jupyter notebooks, and supported data sources across 350+ connectors.</div></a>
      <a class="ref-card" href="https://learn.microsoft.com/en-us/azure/sentinel/manage-data-overview" target="_blank" rel="noopener"><div class="ref-title">Manage data tiers and retention in Microsoft Sentinel</div><div class="ref-desc">Analytics retention (hot), total retention, data lake tier, and XDR default tier — how data flows between tiers, table-level configuration, the relationship between analytics and lake retention, and how to switch tables between analytics and data lake-only mode via the Defender portal.</div></a>
      <a class="ref-card" href="https://learn.microsoft.com/en-us/azure/sentinel/log-plans" target="_blank" rel="noopener"><div class="ref-title">Log retention tiers in Microsoft Sentinel</div><div class="ref-desc">Analytics vs data lake tiers for primary and secondary security data. Covers data classification guidance — which logs to keep in the analytics tier for real-time detection vs which to move to the data lake for cost-effective long-term retention and compliance.</div></a>
      <a class="ref-card" href="https://learn.microsoft.com/en-us/azure/sentinel/billing" target="_blank" rel="noopener"><div class="ref-title">Plan costs and understand pricing and billing</div><div class="ref-desc">Simplified pricing tiers, commitment tier discounts, data lake storage billing with the 6:1 compression rate, data lake query charges on uncompressed data, Jupyter notebook compute costs, and how billing meters transition when onboarding to the data lake.</div></a>
      <a class="ref-card" href="https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-lake-onboarding" target="_blank" rel="noopener"><div class="ref-title">Onboarding to Microsoft Sentinel data lake</div><div class="ref-desc">Prerequisites, required roles (Subscription Owner, Global Admin), onboarding steps from the Defender portal, what changes during provisioning — workspace attachment, automatic mirroring enablement, billing meter transitions, and CMK limitations during preview.</div></a>
      <a class="ref-card" href="https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-lake-connectors" target="_blank" rel="noopener"><div class="ref-title">Set up connectors for the data lake</div><div class="ref-desc">How existing Sentinel data connectors work with the data lake — automatic mirroring after onboarding, configuring analytics-only vs data lake-only ingestion, XDR table ingestion, retention configuration per connector, and which custom table types are supported for mirroring.</div></a>
      <a class="ref-card" href="https://learn.microsoft.com/en-us/rest/api/loganalytics/tables/create-or-update" target="_blank" rel="noopener"><div class="ref-title">Tables — Create Or Update (REST API)</div><div class="ref-desc">API reference for modifying retentionInDays and totalRetentionInDays on workspace tables. PATCH modifies only specified properties; PUT resets omitted properties to defaults. Covers allowed value ranges, retentionInDaysAsDefault, and provisioningState responses.</div></a>
      <a class="ref-card" href="https://learn.microsoft.com/en-us/azure/azure-monitor/logs/cost-logs" target="_blank" rel="noopener"><div class="ref-title">Azure Monitor Logs cost calculations and options</div><div class="ref-desc">Detailed pricing model for the analytics tier, long-term retention, and data lake storage. Covers ingestion costs, the 31-day included retention, extended analytics retention pricing, commitment tier savings, and how to optimise costs by moving data between tiers.</div></a>
    </div>
  </div>
  <div class="tab-panel" id="tab-recs">
    <h2>Recommendations &amp; Warnings</h2>
    $($recWarningsHtml.ToString())
  </div>
  <div class="tab-panel" id="tab-changes">
    <h2>Tables — Will Change <span class="tab-count" style="font-size:.8rem">$changeCount</span></h2>
    $changeTableHtml
  </div>
  <div class="tab-panel" id="tab-unchanged">
    <h2>Tables — No Change <span class="tab-count" style="font-size:.8rem">$unchangedCount</span></h2>
    $unchangedTableHtml
  </div>
  <div class="tab-panel" id="tab-lakemigration">
    <h2>Lake Migration Cost Analysis <span class="tab-count" style="font-size:.8rem">$lakeMigrationCount tables &middot; $lakeMoveCandidates candidates</span></h2>
    $lakeMigrationHtml
  </div>
  <footer class="report-footer">Sentinel Retention Assessment Report &middot; Generated $reportDate &middot; API 2025-07-01</footer>
</div>
<script>
document.querySelectorAll('.tab-btn').forEach(b=>{b.addEventListener('click',()=>{document.querySelectorAll('.tab-btn').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.tab-panel').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.getElementById('tab-'+b.dataset.tab).classList.add('active')})});
document.querySelectorAll('.tab-panel').forEach(panel=>{const s=panel.querySelector('.tbl-search'),pf=panel.querySelector('.tbl-plan-filter'),eb=panel.querySelector('.tbl-expand'),tbl=panel.querySelector('.main-table');if(!tbl)return;const rows=tbl.querySelectorAll('tbody tr');function filt(){const q=s?s.value.toLowerCase():'',p=pf?pf.value:'all';rows.forEach(r=>{if(r.classList.contains('detail-row'))return;const n=(r.querySelector('.table-name')||r.cells[0]).textContent.toLowerCase(),pl=r.dataset.plan||'',v=(!q||n.includes(q))&&(p==='all'||pl===p);r.classList.toggle('hidden-row',!v);const d=r.nextElementSibling;if(d&&d.classList.contains('detail-row')&&!v){d.style.display='none';r.classList.remove('open')}})}if(s)s.addEventListener('input',filt);if(pf)pf.addEventListener('change',filt);if(eb)eb.addEventListener('click',function(){const ds=tbl.querySelectorAll('.detail-row'),ts=tbl.querySelectorAll('.toggle-row'),o=this.textContent.includes('Collapse');ds.forEach(d=>d.style.display=o?'none':'table-row');ts.forEach(t=>t.classList.toggle('open',!o));this.textContent=o?'Expand all':'Collapse all'})});
document.querySelectorAll('.toggle-row').forEach(r=>{r.addEventListener('click',()=>{const d=r.nextElementSibling;if(d&&d.classList.contains('detail-row')){const o=d.style.display!=='none';d.style.display=o?'none':'table-row';r.classList.toggle('open',!o)}})});
document.querySelectorAll('.main-table').forEach(tbl=>{let sc=-1,sa=true;tbl.querySelectorAll('thead th[data-col]').forEach(th=>{th.addEventListener('click',()=>{const c=parseInt(th.dataset.col);if(sc===c)sa=!sa;else{sc=c;sa=true}const tb=tbl.querySelector('tbody'),rows=Array.from(tb.querySelectorAll('tr:not(.detail-row)'));rows.sort((a,b)=>{const at=(a.cells[c]||{}).textContent||'',bt=(b.cells[c]||{}).textContent||'';return sa?at.localeCompare(bt):bt.localeCompare(at)});rows.forEach(r=>{tb.appendChild(r);const nx=tb.querySelector('tr.detail-row');})})})});
</script>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding utf8NoBOM
Write-Host " Done" -ForegroundColor Green
Write-Host "`n  Report saved to: $OutputPath`n" -ForegroundColor Cyan

#endregion
