#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Performs a full audit of Azure Monitor Data Collection Rules (DCRs) across all accessible subscriptions.

.DESCRIPTION
    This script enumerates every Data Collection Rule in scope, extracts detailed configuration
    (data sources, destinations, data flows, stream declarations, endpoints, associations, identity),
    and produces both a JSON export and an HTML report for migration planning.

    The JSON export preserves the complete DCR configuration for programmatic re-creation.
    The HTML report provides a human-readable summary suitable for stakeholder review.

.PARAMETER SubscriptionId
    Optional. One or more subscription IDs to scope the audit. If omitted, all accessible subscriptions are scanned.

.PARAMETER OutputDirectory
    Directory to write the report and JSON files. Defaults to ./DCR-Audit-<timestamp>.

.PARAMETER IncludeAssociations
    Switch. When set, queries Data Collection Rule Associations (DCRAs) for each rule.
    This adds significant API call overhead in large environments.

.PARAMETER ExportARM
    Switch. When set, exports each DCR as an ARM template JSON file for direct redeployment.

.EXAMPLE
    .\Invoke-DCRAudit.ps1
    Audits all subscriptions the current identity can access.

.EXAMPLE
    .\Invoke-DCRAudit.ps1 -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -IncludeAssociations
    Audits a single subscription and includes DCRA lookups.

.EXAMPLE
    .\Invoke-DCRAudit.ps1 -OutputDirectory "C:\Audits\DCR" -ExportARM
    Exports full ARM templates alongside the report.

.NOTES
    Author  : Toby G
    Version : 1.0.0
    Date    : 2026-03-19
    Requires: Az.Accounts
              Contributor or Reader on target subscriptions
              Uses Invoke-AzRestMethod (REST API 2024-03-11) for full unflattened DCR properties
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionId
    ,
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory
    ,
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAssociations
    ,
    [Parameter(Mandatory = $false)]
    [switch]$ExportARM
)

#region ── Helper Functions ──────────────────────────────────────────────────────

function Write-AuditLog {
    [CmdletBinding()]
    param(
        [string]$Message
        ,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $colour = switch ($Level) {
        'Info'    { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error'   { 'Red' }
        'Success' { 'Green' }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colour
}

function Get-DCRAssociations {
    <#
    .SYNOPSIS
        Retrieves all Data Collection Rule Associations for a given DCR,
        parsing the associated resource details from each association ID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DataCollectionRuleId
    )

    try {
        $apiVersion = '2024-03-11'
        $uri = "https://management.azure.com${DataCollectionRuleId}/associations?api-version=${apiVersion}"
        $response = Invoke-AzRestMethod -Uri $uri -Method GET

        if ($response.StatusCode -eq 200) {
            $content = $response.Content | ConvertFrom-Json
            $results = [System.Collections.Generic.List[PSCustomObject]]::new()

            foreach ($assoc in $content.value) {
                # The association ID embeds the full resource path:
                # /subscriptions/.../resourceGroups/.../providers/Microsoft.Compute/virtualMachines/myVm/providers/Microsoft.Insights/dataCollectionRuleAssociations/...
                # Extract the resource portion (everything before /providers/Microsoft.Insights/dataCollectionRuleAssociations)
                $resourceId = $null
                $resourceName = $null
                $resourceType = $null
                $resourceGroup = $null

                if ($assoc.id -match '^(.+)/providers/Microsoft\.Insights/dataCollectionRuleAssociations/') {
                    $resourceId = $Matches[1]

                    # Extract resource name (last segment)
                    if ($resourceId -match '/([^/]+)$') {
                        $resourceName = $Matches[1]
                    }

                    # Extract resource group
                    if ($resourceId -match '/resourceGroups/([^/]+)') {
                        $resourceGroup = $Matches[1]
                    }

                    # Extract resource type (provider/type pair, e.g. Microsoft.Compute/virtualMachines)
                    # Match the last provider/type pair before the resource name
                    if ($resourceId -match '/providers/([^/]+/[^/]+)/[^/]+$') {
                        $resourceType = $Matches[1]
                    }
                }

                $results.Add([PSCustomObject]@{
                    AssociationName           = $assoc.name
                    AssociationId             = $assoc.id
                    ResourceName              = $resourceName
                    ResourceType              = $resourceType
                    ResourceGroup             = $resourceGroup
                    ResourceId                = $resourceId
                    DataCollectionEndpointId  = $assoc.properties.dataCollectionEndpointId
                    DataCollectionRuleId      = $assoc.properties.dataCollectionRuleId
                    Description               = $assoc.properties.description
                })
            }

            return $results
        }
        else {
            Write-AuditLog "Failed to retrieve associations for DCR (HTTP $($response.StatusCode))" -Level Warning
            return @()
        }
    }
    catch {
        Write-AuditLog "Error retrieving associations: $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function ConvertTo-ARMTemplate {
    <#
    .SYNOPSIS
        Converts a DCR object into a deployable ARM template.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$DCR
    )

    $template = [ordered]@{
        '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
        contentVersion = '1.0.0.0'
        parameters     = @{}
        resources      = @(
            [ordered]@{
                type       = 'Microsoft.Insights/dataCollectionRules'
                apiVersion = '2024-03-11'
                name       = $DCR.Name
                location   = $DCR.Location
                tags       = if ($DCR.Tags) { $DCR.Tags } else { @{} }
                kind       = if ($DCR.Kind) { $DCR.Kind } else { $null }
                identity   = if ($DCR.Identity) { $DCR.Identity } else { $null }
                properties = $DCR.Properties
            }
        )
    }

    return $template | ConvertTo-Json -Depth 30
}

function Get-DataSourceSummary {
    <#
    .SYNOPSIS
        Extracts a structured summary of all data source types configured in a DCR.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$DataSources
    )

    $summary = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Performance counters
    if ($DataSources.performanceCounters) {
        foreach ($pc in $DataSources.performanceCounters) {
            $summary.Add([PSCustomObject]@{
                Type                = 'PerformanceCounters'
                Name                = $pc.name
                Streams             = ($pc.streams -join ', ')
                SamplingFrequency   = "$($pc.samplingFrequencyInSeconds)s"
                CounterSpecifiers   = ($pc.counterSpecifiers -join '; ')
            })
        }
    }

    # Windows Event Logs
    if ($DataSources.windowsEventLogs) {
        foreach ($wel in $DataSources.windowsEventLogs) {
            $summary.Add([PSCustomObject]@{
                Type                = 'WindowsEventLogs'
                Name                = $wel.name
                Streams             = ($wel.streams -join ', ')
                SamplingFrequency   = 'N/A'
                CounterSpecifiers   = ($wel.xPathQueries -join '; ')
            })
        }
    }

    # Syslog
    if ($DataSources.syslog) {
        foreach ($sl in $DataSources.syslog) {
            $summary.Add([PSCustomObject]@{
                Type                = 'Syslog'
                Name                = $sl.name
                Streams             = ($sl.streams -join ', ')
                SamplingFrequency   = 'N/A'
                CounterSpecifiers   = "Facilities: $($sl.facilityNames -join ', ') | Levels: $($sl.logLevels -join ', ')"
            })
        }
    }

    # Extensions (e.g., Defender, Sentinel agents)
    if ($DataSources.extensions) {
        foreach ($ext in $DataSources.extensions) {
            $summary.Add([PSCustomObject]@{
                Type                = 'Extension'
                Name                = $ext.name
                Streams             = ($ext.streams -join ', ')
                SamplingFrequency   = 'N/A'
                CounterSpecifiers   = "ExtensionName: $($ext.extensionName)"
            })
        }
    }

    # Log files (custom text/JSON logs)
    if ($DataSources.logFiles) {
        foreach ($lf in $DataSources.logFiles) {
            $summary.Add([PSCustomObject]@{
                Type                = 'LogFiles'
                Name                = $lf.name
                Streams             = ($lf.streams -join ', ')
                SamplingFrequency   = 'N/A'
                CounterSpecifiers   = "Format: $($lf.format) | Paths: $(if ($lf.settings.text.recordStartTimestampFormat) { $lf.settings.text.recordStartTimestampFormat } else { 'N/A' })"
            })
        }
    }

    # IIS Logs
    if ($DataSources.iisLogs) {
        foreach ($iis in $DataSources.iisLogs) {
            $summary.Add([PSCustomObject]@{
                Type                = 'IISLogs'
                Name                = $iis.name
                Streams             = ($iis.streams -join ', ')
                SamplingFrequency   = 'N/A'
                CounterSpecifiers   = "LogDirectories: $($iis.logDirectories -join '; ')"
            })
        }
    }

    # Platform Telemetry
    if ($DataSources.platformTelemetry) {
        foreach ($pt in $DataSources.platformTelemetry) {
            $summary.Add([PSCustomObject]@{
                Type                = 'PlatformTelemetry'
                Name                = $pt.name
                Streams             = ($pt.streams -join ', ')
                SamplingFrequency   = 'N/A'
                CounterSpecifiers   = ''
            })
        }
    }

    # Prometheus forwarder
    if ($DataSources.prometheusForwarder) {
        foreach ($pf in $DataSources.prometheusForwarder) {
            $summary.Add([PSCustomObject]@{
                Type                = 'PrometheusForwarder'
                Name                = $pf.name
                Streams             = ($pf.streams -join ', ')
                SamplingFrequency   = 'N/A'
                CounterSpecifiers   = "LabelIncludeFilter: $($pf.labelIncludeFilter | ConvertTo-Json -Compress -Depth 5)"
            })
        }
    }

    # Data imports (e.g., Event Hubs)
    if ($DataSources.dataImports) {
        $summary.Add([PSCustomObject]@{
            Type                = 'DataImports'
            Name                = 'EventHub'
            Streams             = if ($DataSources.dataImports.eventHub.stream) { $DataSources.dataImports.eventHub.stream } else { 'N/A' }
            SamplingFrequency   = 'N/A'
            CounterSpecifiers   = "ConsumerGroup: $(if ($DataSources.dataImports.eventHub.consumerGroup) { $DataSources.dataImports.eventHub.consumerGroup } else { 'N/A' })"
        })
    }

    # ETW Providers (Event Tracing for Windows)
    if ($DataSources.etwProviders) {
        foreach ($etw in $DataSources.etwProviders) {
            $eventIds = if ($etw.eventIds) { $etw.eventIds -join ', ' } else { 'All' }
            $summary.Add([PSCustomObject]@{
                Type                = 'EtwProviders'
                Name                = $etw.name
                Streams             = ($etw.streams -join ', ')
                SamplingFrequency   = 'N/A'
                CounterSpecifiers   = "Provider: $($etw.provider) | EventIds: $eventIds | Level: $($etw.logLevel) | Keyword: $($etw.keyword)"
            })
        }
    }

    # Windows Firewall Logs
    if ($DataSources.windowsFirewallLogs) {
        foreach ($wfl in $DataSources.windowsFirewallLogs) {
            $summary.Add([PSCustomObject]@{
                Type                = 'WindowsFirewallLogs'
                Name                = $wfl.name
                Streams             = ($wfl.streams -join ', ')
                SamplingFrequency   = 'N/A'
                CounterSpecifiers   = ''
            })
        }
    }

    return $summary
}

function Get-DestinationSummary {
    <#
    .SYNOPSIS
        Extracts a structured summary of all destination types configured in a DCR.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Destinations
    )

    $summary = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Log Analytics workspaces
    if ($Destinations.logAnalytics) {
        foreach ($la in $Destinations.logAnalytics) {
            $summary.Add([PSCustomObject]@{
                Type         = 'LogAnalytics'
                Name         = $la.name
                ResourceId   = $la.workspaceResourceId
                Details      = "WorkspaceId: $($la.workspaceId)"
            })
        }
    }

    # Azure Monitor Metrics
    if ($Destinations.azureMonitorMetrics) {
        $summary.Add([PSCustomObject]@{
            Type         = 'AzureMonitorMetrics'
            Name         = $Destinations.azureMonitorMetrics.name
            ResourceId   = 'N/A (platform)'
            Details      = 'Azure Monitor Metrics sink'
        })
    }

    # Storage accounts (blob/table)
    if ($Destinations.storageAccounts) {
        foreach ($sa in $Destinations.storageAccounts) {
            $summary.Add([PSCustomObject]@{
                Type         = 'StorageAccount'
                Name         = $sa.name
                ResourceId   = $sa.storageAccountResourceId
                Details      = "Container: $($sa.containerName)"
            })
        }
    }

    # Storage blobs direct
    if ($Destinations.storageBlobsDirect) {
        foreach ($sb in $Destinations.storageBlobsDirect) {
            $summary.Add([PSCustomObject]@{
                Type         = 'StorageBlobsDirect'
                Name         = $sb.name
                ResourceId   = $sb.storageAccountResourceId
                Details      = "Container: $($sb.containerName)"
            })
        }
    }

    # Storage tables direct
    if ($Destinations.storageTablesDirect) {
        foreach ($st in $Destinations.storageTablesDirect) {
            $summary.Add([PSCustomObject]@{
                Type         = 'StorageTablesDirect'
                Name         = $st.name
                ResourceId   = $st.storageAccountResourceId
                Details      = "Table: $($st.tableName)"
            })
        }
    }

    # Event Hubs
    if ($Destinations.eventHubs) {
        foreach ($eh in $Destinations.eventHubs) {
            $summary.Add([PSCustomObject]@{
                Type         = 'EventHub'
                Name         = $eh.name
                ResourceId   = $eh.eventHubResourceId
                Details      = ''
            })
        }
    }

    # Event Hubs direct
    if ($Destinations.eventHubsDirect) {
        foreach ($ehd in $Destinations.eventHubsDirect) {
            $summary.Add([PSCustomObject]@{
                Type         = 'EventHubsDirect'
                Name         = $ehd.name
                ResourceId   = $ehd.eventHubResourceId
                Details      = ''
            })
        }
    }

    # Monitoring accounts (Prometheus)
    if ($Destinations.monitoringAccounts) {
        foreach ($ma in $Destinations.monitoringAccounts) {
            $summary.Add([PSCustomObject]@{
                Type         = 'MonitoringAccount'
                Name         = $ma.name
                ResourceId   = $ma.accountResourceId
                Details      = 'Azure Monitor workspace (Prometheus)'
            })
        }
    }

    return $summary
}

function New-HTMLReport {
    <#
    .SYNOPSIS
        Generates a styled HTML report from the audit results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Generic.List[PSCustomObject]]$AuditResults
        ,
        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $totalDCRs       = $AuditResults.Count
    $subscriptions    = ($AuditResults | Select-Object -ExpandProperty SubscriptionName -Unique).Count
    $dcrKinds         = $AuditResults | ForEach-Object {
        $clone = $_ | Select-Object *
        if (-not $clone.Kind) { $clone.Kind = 'Standard' }
        $clone
    } | Group-Object Kind | Sort-Object Count -Descending
    $dcrByRegion      = $AuditResults | Group-Object Location | Sort-Object Count -Descending
    $reportDate       = Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC'

    # Build summary cards
    $kindCards = ($dcrKinds | ForEach-Object {
        "<div class='card'><div class='card-value'>$($_.Count)</div><div class='card-label'>$($_.Name)</div></div>"
    }) -join "`n"

    # Build DCR detail rows
    $dcrRows = [System.Text.StringBuilder]::new()
    foreach ($dcr in ($AuditResults | Sort-Object SubscriptionName, Name)) {
        $dsCount   = ($dcr.DataSourceSummary | Measure-Object).Count
        $destCount = ($dcr.DestinationSummary | Measure-Object).Count
        $flowCount = ($dcr.DataFlows | Measure-Object).Count

        # Data source details
        $dsDetails = if ($dcr.DataSourceSummary.Count -gt 0) {
            $rows = ($dcr.DataSourceSummary | ForEach-Object {
                "<tr><td>$($_.Type)</td><td>$($_.Name)</td><td>$($_.Streams)</td><td>$($_.SamplingFrequency)</td><td class='mono'>$([System.Web.HttpUtility]::HtmlEncode($_.CounterSpecifiers))</td></tr>"
            }) -join "`n"
            "<table class='detail-table'><thead><tr><th>Type</th><th>Name</th><th>Streams</th><th>Frequency</th><th>Details</th></tr></thead><tbody>$rows</tbody></table>"
        }
        else { '<p class="muted">No data sources configured</p>' }

        # Destination details
        $destDetails = if ($dcr.DestinationSummary.Count -gt 0) {
            $rows = ($dcr.DestinationSummary | ForEach-Object {
                "<tr><td>$($_.Type)</td><td>$($_.Name)</td><td class='mono'>$([System.Web.HttpUtility]::HtmlEncode($_.ResourceId))</td><td>$($_.Details)</td></tr>"
            }) -join "`n"
            "<table class='detail-table'><thead><tr><th>Type</th><th>Name</th><th>Resource ID</th><th>Details</th></tr></thead><tbody>$rows</tbody></table>"
        }
        else { '<p class="muted">No destinations configured</p>' }

        # Data flow details
        $flowDetails = if ($dcr.DataFlows.Count -gt 0) {
            $rows = ($dcr.DataFlows | ForEach-Object {
                $streams          = if ($_.streams) { $_.streams -join ', ' } else { 'N/A' }
                $destinations     = if ($_.destinations) { $_.destinations -join ', ' } else { 'N/A' }
                $outputStream     = if ($_.outputStream) { $_.outputStream } else { 'N/A' }
                $transformKql     = if ($_.transformKql) { [System.Web.HttpUtility]::HtmlEncode($_.transformKql) } else { 'N/A' }
                $builtInTransform = if ($_.builtInTransform) { $_.builtInTransform } else { 'N/A' }
                $captureOverflow  = if ($null -ne $_.captureOverflow) { $_.captureOverflow.ToString() } else { 'N/A' }
                "<tr><td>$streams</td><td>$destinations</td><td>$outputStream</td><td class='mono'>$transformKql</td><td>$builtInTransform</td><td>$captureOverflow</td></tr>"
            }) -join "`n"
            "<table class='detail-table'><thead><tr><th>Streams</th><th>Destinations</th><th>Output Stream</th><th>Transform KQL</th><th>Built-in Transform</th><th>Capture Overflow</th></tr></thead><tbody>$rows</tbody></table>"
        }
        else { '<p class="muted">No data flows configured</p>' }

        # Stream declarations
        $streamDetails = if ($dcr.StreamDeclarations -and $dcr.StreamDeclarations.PSObject.Properties.Count -gt 0) {
            $rows = ($dcr.StreamDeclarations.PSObject.Properties | ForEach-Object {
                $columns = if ($_.Value.columns) {
                    ($_.Value.columns | ForEach-Object { "$($_.name) ($($_.type))" }) -join ', '
                }
                else { 'N/A' }
                "<tr><td class='mono'>$($_.Name)</td><td>$columns</td></tr>"
            }) -join "`n"
            "<table class='detail-table'><thead><tr><th>Stream Name</th><th>Columns</th></tr></thead><tbody>$rows</tbody></table>"
        }
        else { '<p class="muted">No custom stream declarations</p>' }

        # Associations
        $assocDetails = if ($dcr.Associations -and $dcr.Associations.Count -gt 0) {
            $rows = ($dcr.Associations | ForEach-Object {
                $resName  = if ($_.ResourceName) { [System.Web.HttpUtility]::HtmlEncode($_.ResourceName) } else { 'N/A' }
                $resType  = if ($_.ResourceType) { [System.Web.HttpUtility]::HtmlEncode($_.ResourceType) } else { 'N/A' }
                $resRG    = if ($_.ResourceGroup) { [System.Web.HttpUtility]::HtmlEncode($_.ResourceGroup) } else { 'N/A' }
                $endpoint = if ($_.DataCollectionEndpointId) { [System.Web.HttpUtility]::HtmlEncode($_.DataCollectionEndpointId) } else { 'No endpoint configured' }
                "<tr><td>$resName</td><td>$resType</td><td>$resRG</td><td class='mono'>$endpoint</td></tr>"
            }) -join "`n"
            "<table class='detail-table'><thead><tr><th>Resource Name</th><th>Type</th><th>Resource Group</th><th>Data Collection Endpoint</th></tr></thead><tbody>$rows</tbody></table>"
        }
        elseif ($dcr.AssociationsQueried) {
            '<p class="muted">No associated resources found</p>'
        }
        else {
            '<p class="muted">Not queried (use -IncludeAssociations switch)</p>'
        }

        # Endpoint
        $endpointInfo = if ($dcr.DataCollectionEndpointId) {
            "<code>$([System.Web.HttpUtility]::HtmlEncode($dcr.DataCollectionEndpointId))</code>"
        }
        else { '<span class="muted">None</span>' }

        # Identity
        $identityInfo = if ($dcr.Identity) {
            $idType = $dcr.Identity.type
            $uaIds = if ($dcr.Identity.userAssignedIdentities) {
                ($dcr.Identity.userAssignedIdentities.PSObject.Properties | ForEach-Object { $_.Name }) -join '; '
            } else { '' }
            if ($uaIds) { "<code>$idType</code><br/><span class='mono' style='font-size:0.8em;'>$([System.Web.HttpUtility]::HtmlEncode($uaIds))</span>" }
            else { "<code>$idType</code>" }
        }
        else { '<span class="muted">None</span>' }

        # Endpoints (Direct ingestion URLs)
        $endpointsInfo = if ($dcr.Endpoints) {
            $parts = @()
            if ($dcr.Endpoints.logsIngestion)    { $parts += "<tr><td>Logs Ingestion</td><td class='mono'>$([System.Web.HttpUtility]::HtmlEncode($dcr.Endpoints.logsIngestion))</td></tr>" }
            if ($dcr.Endpoints.metricsIngestion) { $parts += "<tr><td>Metrics Ingestion</td><td class='mono'>$([System.Web.HttpUtility]::HtmlEncode($dcr.Endpoints.metricsIngestion))</td></tr>" }
            if ($parts.Count -gt 0) {
                "<table class='detail-table'><thead><tr><th>Endpoint</th><th>URL</th></tr></thead><tbody>$($parts -join "`n")</tbody></table>"
            } else { '<span class="muted">None</span>' }
        }
        else { '<span class="muted">None</span>' }

        # Agent Settings
        $agentSettingsInfo = if ($dcr.AgentSettings -and $dcr.AgentSettings.logs) {
            $rows = ($dcr.AgentSettings.logs | ForEach-Object {
                "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($_.name))</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.value))</td></tr>"
            }) -join "`n"
            "<table class='detail-table'><thead><tr><th>Setting</th><th>Value</th></tr></thead><tbody>$rows</tbody></table>"
        }
        else { '<span class="muted">None</span>' }

        # References (enrichment data)
        $referencesInfo = if ($dcr.References) {
            "<code class='resource-id'>$([System.Web.HttpUtility]::HtmlEncode(($dcr.References | ConvertTo-Json -Compress -Depth 10)))</code>"
        }
        else { '<span class="muted">None</span>' }

        # systemData (created/modified audit trail)
        $systemDataInfo = if ($dcr.SystemData) {
            $sd = $dcr.SystemData
            $rows = @()
            if ($sd.createdBy)        { $rows += "<tr><td>Created By</td><td>$([System.Web.HttpUtility]::HtmlEncode($sd.createdBy)) ($($sd.createdByType))</td></tr>" }
            if ($sd.createdAt)        { $rows += "<tr><td>Created At</td><td>$($sd.createdAt)</td></tr>" }
            if ($sd.lastModifiedBy)   { $rows += "<tr><td>Last Modified By</td><td>$([System.Web.HttpUtility]::HtmlEncode($sd.lastModifiedBy)) ($($sd.lastModifiedByType))</td></tr>" }
            if ($sd.lastModifiedAt)   { $rows += "<tr><td>Last Modified At</td><td>$($sd.lastModifiedAt)</td></tr>" }
            if ($rows.Count -gt 0) {
                "<table class='detail-table'><thead><tr><th>Property</th><th>Value</th></tr></thead><tbody>$($rows -join "`n")</tbody></table>"
            } else { '<span class="muted">None</span>' }
        }
        else { '<span class="muted">None</span>' }

        [void]$dcrRows.Append(@"
        <div class="dcr-card">
            <div class="dcr-header" onclick="this.parentElement.classList.toggle('expanded')">
                <div class="dcr-header-content">
                    <div class="dcr-title">
                        <span class="dcr-name">$([System.Web.HttpUtility]::HtmlEncode($dcr.Name))</span>
                        <span class="dcr-kind badge">$(if ($dcr.Kind) { $dcr.Kind } else { 'Standard' })</span>
                        <span class="dcr-prov badge prov-$($dcr.ProvisioningState.ToLower())">$($dcr.ProvisioningState)</span>
                    </div>
                    <div class="dcr-meta">
                        <span>$($dcr.SubscriptionName)</span>
                        <span>$($dcr.ResourceGroupName)</span>
                        <span>$($dcr.Location)</span>
                        <span>Sources: $dsCount</span>
                        <span>Destinations: $destCount</span>
                        <span>Flows: $flowCount</span>
                    </div>
                </div>
            </div>
            <div class="dcr-body">
                <div class="section">
                    <h4>Resource ID</h4>
                    <code class="resource-id">$([System.Web.HttpUtility]::HtmlEncode($dcr.ResourceId))</code>
                </div>
                <div class="section">
                    <h4>Description</h4>
                    $(if ($dcr.Description) { "<p>$([System.Web.HttpUtility]::HtmlEncode($dcr.Description))</p>" } else { '<span class="muted">None</span>' })
                </div>
                <div class="section">
                    <h4>Immutable ID / Etag</h4>
                    <code>$($dcr.ImmutableId)</code> &nbsp; <span class="muted">etag:</span> <code>$($dcr.Etag)</code>
                </div>
                <div class="section">
                    <h4>Data Collection Endpoint</h4>
                    $endpointInfo
                </div>
                <div class="section">
                    <h4>Ingestion Endpoints (Direct)</h4>
                    $endpointsInfo
                </div>
                <div class="section">
                    <h4>Identity</h4>
                    $identityInfo
                </div>
                <div class="section">
                    <h4>Data Sources</h4>
                    $dsDetails
                </div>
                <div class="section">
                    <h4>Destinations</h4>
                    $destDetails
                </div>
                <div class="section">
                    <h4>Data Flows</h4>
                    $flowDetails
                </div>
                <div class="section">
                    <h4>Custom Stream Declarations</h4>
                    $streamDetails
                </div>
                <div class="section">
                    <h4>Agent Settings</h4>
                    $agentSettingsInfo
                </div>
                <div class="section">
                    <h4>Enrichment References</h4>
                    $referencesInfo
                </div>
                <div class="section">
                    <h4>Resources (Associations)</h4>
                    $assocDetails
                </div>
                <div class="section">
                    <h4>Audit Trail (systemData)</h4>
                    $systemDataInfo
                </div>
                <div class="section">
                    <h4>Tags</h4>
                    <code>$( if ($dcr.Tags) { $dcr.Tags | ConvertTo-Json -Compress } else { '{}' } )</code>
                </div>
            </div>
        </div>
"@)
    }

    # Region breakdown table
    $regionRows = ($dcrByRegion | ForEach-Object {
        "<tr><td>$($_.Name)</td><td>$($_.Count)</td></tr>"
    }) -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DCR Audit Report</title>
    <style>
        :root {
            --bg: #0d1117; --surface: #161b22; --border: #30363d;
            --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
            --green: #3fb950; --yellow: #d29922; --red: #f85149;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
               background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
        .container { max-width: 1400px; margin: 0 auto; }

        h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
        h2 { font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
        h4 { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin-bottom: 0.5rem; }

        .subtitle { color: var(--muted); margin-bottom: 2rem; }
        .muted { color: var(--muted); font-style: italic; }
        .mono, code { font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 0.85em; }
        code { background: var(--bg); padding: 2px 6px; border-radius: 3px; word-break: break-all; }
        .resource-id { display: block; margin-top: 0.25rem; }

        /* Summary cards */
        .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
                padding: 1.25rem 1.5rem; min-width: 140px; text-align: center; }
        .card-value { font-size: 2rem; font-weight: 700; color: var(--accent); }
        .card-label { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }

        /* DCR cards */
        .dcr-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
                    margin-bottom: 0.75rem; overflow: hidden; }
        .dcr-header { padding: 1rem 1.25rem; cursor: pointer; user-select: none;
                      display: flex; align-items: flex-start; gap: 0; }
        .dcr-header:hover { background: rgba(88, 166, 255, 0.04); }
        .dcr-header::before { content: '\25B6'; margin-right: 0.75rem; font-size: 0.7rem; color: var(--muted);
                              display: block; flex-shrink: 0; transition: transform 0.15s; margin-top: 0.35rem; }
        .dcr-card.expanded .dcr-header::before { transform: rotate(90deg); }
        .dcr-header-content { flex: 1; min-width: 0; }

        .dcr-title { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
        .dcr-name { font-weight: 600; font-size: 1rem; }
        .badge { font-size: 0.7rem; padding: 2px 8px; border-radius: 12px; font-weight: 500; }
        .dcr-kind { background: rgba(88, 166, 255, 0.15); color: var(--accent); }
        .prov-succeeded { background: rgba(63, 185, 80, 0.15); color: var(--green); }
        .prov-failed { background: rgba(248, 81, 73, 0.15); color: var(--red); }
        .prov-creating, .prov-updating { background: rgba(210, 153, 34, 0.15); color: var(--yellow); }

        .dcr-meta { display: flex; gap: 1.25rem; font-size: 0.8rem; color: var(--muted); margin-top: 0.35rem; flex-wrap: wrap; }

        .dcr-body { display: none; padding: 0 1.25rem 1.25rem; border-top: 1px solid var(--border); }
        .dcr-card.expanded .dcr-body { display: block; }

        .section { margin-top: 1.25rem; }
        .section:first-child { margin-top: 0.75rem; }

        /* Detail tables */
        .detail-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; margin-top: 0.25rem; }
        .detail-table th { text-align: left; padding: 0.4rem 0.6rem; background: var(--bg);
                           color: var(--muted); font-weight: 600; border-bottom: 2px solid var(--border); }
        .detail-table td { padding: 0.4rem 0.6rem; border-bottom: 1px solid var(--border);
                           vertical-align: top; word-break: break-word; }
        .detail-table tr:last-child td { border-bottom: none; }

        /* Region table */
        .region-table { width: auto; min-width: 300px; }

        /* Filter bar */
        .filter-bar { display: flex; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap; }
        .filter-bar input, .filter-bar select {
            background: var(--surface); border: 1px solid var(--border); color: var(--text);
            padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.85rem; }
        .filter-bar input { flex: 1; min-width: 200px; }
        .filter-bar select { min-width: 160px; }

        @media (max-width: 768px) {
            body { padding: 1rem; }
            .cards { flex-direction: column; }
            .dcr-meta { flex-direction: column; gap: 0.25rem; }
        }

        @media print {
            .dcr-body { display: block !important; }
            .dcr-header::before { display: none; }
            .filter-bar { display: none; }
        }
    </style>
</head>
<body>
<div class="container">
    <h1>Azure Monitor &mdash; Data Collection Rules Audit</h1>
    <p class="subtitle">Generated $reportDate &bull; $totalDCRs rules across $subscriptions subscription(s)</p>

    <div class="cards">
        <div class="card"><div class="card-value">$totalDCRs</div><div class="card-label">Total DCRs</div></div>
        <div class="card"><div class="card-value">$subscriptions</div><div class="card-label">Subscriptions</div></div>
        $kindCards
    </div>

    <h2>Region Distribution</h2>
    <table class="detail-table region-table">
        <thead><tr><th>Region</th><th>Count</th></tr></thead>
        <tbody>$regionRows</tbody>
    </table>

    <h2>Data Collection Rules</h2>

    <div class="filter-bar">
        <input type="text" id="search" placeholder="Filter by name, subscription, resource group..." oninput="filterDCRs()">
        <select id="kindFilter" onchange="filterDCRs()">
            <option value="">All Kinds</option>
        </select>
        <select id="subFilter" onchange="filterDCRs()">
            <option value="">All Subscriptions</option>
        </select>
    </div>

    <div id="dcr-list">
        $($dcrRows.ToString())
    </div>
</div>

<script>
    // Populate filter dropdowns
    const cards = document.querySelectorAll('.dcr-card');
    const kinds = new Set();
    const subs  = new Set();
    cards.forEach(c => {
        const kindEl = c.querySelector('.dcr-kind');
        const metaSpans = c.querySelectorAll('.dcr-meta span');
        if (kindEl) kinds.add(kindEl.textContent.trim());
        if (metaSpans[0]) subs.add(metaSpans[0].textContent.trim());
    });
    const kindSel = document.getElementById('kindFilter');
    const subSel  = document.getElementById('subFilter');
    [...kinds].sort().forEach(k => { const o = document.createElement('option'); o.value = k; o.textContent = k; kindSel.appendChild(o); });
    [...subs].sort().forEach(s  => { const o = document.createElement('option'); o.value = s; o.textContent = s; subSel.appendChild(o); });

    function filterDCRs() {
        const q    = document.getElementById('search').value.toLowerCase();
        const kind = kindSel.value;
        const sub  = subSel.value;
        cards.forEach(c => {
            const text     = c.textContent.toLowerCase();
            const cardKind = c.querySelector('.dcr-kind')?.textContent.trim() || '';
            const cardSub  = c.querySelectorAll('.dcr-meta span')[0]?.textContent.trim() || '';
            const match    = text.includes(q) && (!kind || cardKind === kind) && (!sub || cardSub === sub);
            c.style.display = match ? '' : 'none';
        });
    }
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding utf8
}

#endregion

#region ── Main ──────────────────────────────────────────────────────────────────

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Web

Write-AuditLog '========================================' -Level Info
Write-AuditLog '  DCR Audit Script v1.0.0' -Level Info
Write-AuditLog '========================================' -Level Info

# ── Verify Az context ──
$context = Get-AzContext -ErrorAction SilentlyContinue
if (-not $context) {
    Write-AuditLog 'No Azure context found. Running Connect-AzAccount...' -Level Warning
    Connect-AzAccount | Out-Null
    $context = Get-AzContext
}
Write-AuditLog "Authenticated as: $($context.Account.Id)" -Level Success

# ── Resolve subscriptions ──
if ($SubscriptionId) {
    $subscriptions = foreach ($sid in $SubscriptionId) {
        Get-AzSubscription -SubscriptionId $sid
    }
}
else {
    $subscriptions = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }
}
Write-AuditLog "Subscriptions in scope: $($subscriptions.Count)" -Level Info

# ── Prepare output directory ──
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path (Get-Location) "DCR-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
if ($ExportARM) {
    New-Item -ItemType Directory -Path (Join-Path $OutputDirectory 'ARM') -Force | Out-Null
}
Write-AuditLog "Output directory: $OutputDirectory" -Level Info

# ── Enumerate DCRs ──
$auditResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$totalProcessed = 0
$apiVersion = '2024-03-11'

foreach ($sub in $subscriptions) {
    Write-AuditLog "Scanning subscription: $($sub.Name) ($($sub.Id))" -Level Info
    Set-AzContext -SubscriptionId $sub.Id -Force | Out-Null

    try {
        # Use REST API directly to get the full unflattened DCR JSON
        $listUri = "https://management.azure.com/subscriptions/$($sub.Id)/providers/Microsoft.Insights/dataCollectionRules?api-version=${apiVersion}"
        $listResponse = Invoke-AzRestMethod -Uri $listUri -Method GET -ErrorAction Stop

        if ($listResponse.StatusCode -ne 200) {
            Write-AuditLog "Failed to list DCRs from $($sub.Name) (HTTP $($listResponse.StatusCode))" -Level Warning
            continue
        }

        $listContent = $listResponse.Content | ConvertFrom-Json
        $dcrs = $listContent.value
    }
    catch {
        Write-AuditLog "Failed to retrieve DCRs from $($sub.Name): $($_.Exception.Message)" -Level Warning
        continue
    }

    if (-not $dcrs -or $dcrs.Count -eq 0) {
        Write-AuditLog "  No DCRs found in $($sub.Name)" -Level Info
        continue
    }

    Write-AuditLog "  Found $($dcrs.Count) DCR(s)" -Level Success

    foreach ($dcr in $dcrs) {
        $totalProcessed++
        Write-AuditLog "  [$totalProcessed] Processing: $($dcr.name)" -Level Info

        # Parse the resource ID for resource group
        $resourceGroupName = if ($dcr.id -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { 'Unknown' }

        $props = $dcr.properties

        # Data source summary (properties.dataSources is the raw nested object)
        $dsSummary = if ($props.dataSources) {
            Get-DataSourceSummary -DataSources $props.dataSources
        }
        else { @() }

        # Destination summary
        $destSummary = if ($props.destinations) {
            Get-DestinationSummary -Destinations $props.destinations
        }
        else { @() }

        # Data flows
        $dataFlows = if ($props.dataFlows) { @($props.dataFlows) } else { @() }

        # Stream declarations
        $streamDeclarations = $props.streamDeclarations

        # Associations
        $associations = @()
        if ($IncludeAssociations) {
            $associations = Get-DCRAssociations -DataCollectionRuleId $dcr.id
        }

        $result = [PSCustomObject]@{
            SubscriptionId            = $sub.Id
            SubscriptionName          = $sub.Name
            ResourceGroupName         = $resourceGroupName
            Name                      = $dcr.name
            ResourceId                = $dcr.id
            Location                  = $dcr.location
            Kind                      = $dcr.kind
            Description               = $props.description
            ProvisioningState         = $props.provisioningState
            DataCollectionEndpointId  = $props.dataCollectionEndpointId
            ImmutableId               = $props.immutableId
            Etag                      = $dcr.etag
            Identity                  = $dcr.identity
            Tags                      = $dcr.tags
            # Endpoints (Direct ingestion URLs - logsIngestion / metricsIngestion)
            Endpoints                 = $props.endpoints
            # Agent settings (MaxDiskQuotaInMB, UseTimeReceivedForForwardedEvents, etc.)
            AgentSettings             = $props.agentSettings
            # References (enrichment data - storage blobs for ingestion-time lookups)
            References                = $props.references
            # systemData (createdBy, createdAt, lastModifiedBy, lastModifiedAt)
            SystemData                = $dcr.systemData
            DataSourceSummary         = $dsSummary
            DestinationSummary        = $destSummary
            DataFlows                 = $dataFlows
            StreamDeclarations        = $streamDeclarations
            Associations              = $associations
            AssociationsQueried       = [bool]$IncludeAssociations
            Properties                = $props
            RawDCR                    = $dcr
        }

        $auditResults.Add($result)

        # Export ARM template if requested
        if ($ExportARM) {
            $armJson = ConvertTo-ARMTemplate -DCR @{
                Name       = $dcr.name
                Location   = $dcr.location
                Tags       = $dcr.tags
                Kind       = $dcr.kind
                Identity   = $dcr.identity
                Properties = $props
            }
            $safeName = $dcr.name -replace '[^\w\-\.]', '_'
            $armPath  = Join-Path $OutputDirectory 'ARM' "${safeName}.json"
            $armJson | Out-File -FilePath $armPath -Encoding utf8
        }
    }
}

Write-AuditLog "Audit complete. Total DCRs processed: $($auditResults.Count)" -Level Success

# ── Export JSON ──
$jsonPath = Join-Path $OutputDirectory 'DCR-Audit-Full.json'
$exportData = $auditResults | Select-Object -Property * -ExcludeProperty RawDCR
$exportData | ConvertTo-Json -Depth 30 | Out-File -FilePath $jsonPath -Encoding utf8
Write-AuditLog "JSON export: $jsonPath" -Level Success

# ── Export CSV summary ──
$csvPath = Join-Path $OutputDirectory 'DCR-Audit-Summary.csv'
$csvProperties = @(
    'SubscriptionName'
    , 'ResourceGroupName'
    , 'Name'
    , 'Location'
    , 'Kind'
    , 'ProvisioningState'
    , 'Description'
    , 'DataCollectionEndpointId'
    , 'ImmutableId'
    , @{ Name = 'DataSourceCount';  Expression = { ($_.DataSourceSummary | Measure-Object).Count } }
    , @{ Name = 'DestinationCount'; Expression = { ($_.DestinationSummary | Measure-Object).Count } }
    , @{ Name = 'DataFlowCount';    Expression = { ($_.DataFlows | Measure-Object).Count } }
    , @{ Name = 'AssociationCount'; Expression = { ($_.Associations | Measure-Object).Count } }
    , @{ Name = 'Tags';             Expression = { if ($_.Tags) { $_.Tags | ConvertTo-Json -Compress } else { '{}' } } }
    , 'ResourceId'
)
$auditResults | Select-Object -Property $csvProperties |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
Write-AuditLog "CSV summary: $csvPath" -Level Success

# ── Generate HTML report ──
$htmlPath = Join-Path $OutputDirectory 'DCR-Audit-Report.html'
New-HTMLReport -AuditResults $auditResults -OutputPath $htmlPath
Write-AuditLog "HTML report: $htmlPath" -Level Success

# ── Summary ──
Write-AuditLog '========================================' -Level Info
Write-AuditLog '  Audit Summary' -Level Info
Write-AuditLog '========================================' -Level Info
Write-AuditLog "  Total DCRs:        $($auditResults.Count)" -Level Info
Write-AuditLog "  Subscriptions:     $($subscriptions.Count)" -Level Info
Write-AuditLog "  Output directory:  $OutputDirectory" -Level Info
Write-AuditLog '  Files generated:' -Level Info
Write-AuditLog "    - DCR-Audit-Full.json    (complete structured export)" -Level Info
Write-AuditLog "    - DCR-Audit-Summary.csv  (flat summary for Excel)" -Level Info
Write-AuditLog "    - DCR-Audit-Report.html  (interactive visual report)" -Level Info
if ($ExportARM) {
    $armCount = (Get-ChildItem -Path (Join-Path $OutputDirectory 'ARM') -Filter '*.json').Count
    Write-AuditLog "    - ARM/*.json             ($armCount ARM templates)" -Level Info
}
Write-AuditLog '========================================' -Level Info

# ── Return results for pipeline use ──
return $auditResults

#endregion
