<#
.SYNOPSIS
    Export Microsoft Sentinel analytical rules with data connector and table requirements analysis.

.DESCRIPTION
    This script exports all Microsoft Sentinel analytical rules from a specified workspace and analyzes their
    data connector and table dependencies. It combines template-based data connector information with KQL 
    query analysis to provide comprehensive coverage reporting.

.PARAMETER SubscriptionId
    The Azure subscription ID containing the Sentinel workspace.

.PARAMETER ResourceGroupName
    The name of the resource group containing the Sentinel workspace.

.PARAMETER WorkspaceName
    The name of the Log Analytics workspace where Sentinel is deployed.

.PARAMETER OutputPath
    The path where the CSV output file will be saved. Defaults to ".\SentinelRules_DataConnector_Analysis.csv"

.EXAMPLE
    .\Export-SentinelRules.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "rg-sentinel" -WorkspaceName "law-sentinel"

.EXAMPLE
    .\Export-SentinelRules.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "rg-sentinel" -WorkspaceName "law-sentinel" -OutputPath "C:\Reports\SentinelAnalysis.csv"

.NOTES
    Author: TobyG
    Version: 1.0
    Requires: Az.Accounts, Az.SecurityInsights PowerShell modules
    
    The script outputs the following columns in the CSV:
    - RuleName: Display name of the analytical rule
    - Enabled: Whether the rule is currently enabled
    - Severity: Rule severity level (Informational, Low, Medium, High, Critical)
    - TemplateDataConnectors: Data connectors specified in the rule template
    - AllRequiredConnectors: Combined list of all required data connectors
    - RequiredTables: Log Analytics tables used by the rule query
    - ConnectorCount: Number of unique data connectors required
    - TableCount: Number of unique tables used in the query
    - Description: Rule description
    - RuleType: Type of analytical rule (Scheduled, NRT, etc.)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Azure subscription ID")]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Resource group name containing the Sentinel workspace")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory = $true, HelpMessage = "Log Analytics workspace name where Sentinel is deployed")]
    [ValidateNotNullOrEmpty()]
    [string]$WorkspaceName,
    
    [Parameter(Mandatory = $false, HelpMessage = "Output CSV file path")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".\SentinelRules_DataConnector_Analysis.csv"
)

#region Module Management
<#
.SYNOPSIS
    Installs and imports required Azure PowerShell modules.

.DESCRIPTION
    Checks for the presence of required Azure modules and installs them if missing.
    Imports the modules into the current session.
#>
function Install-RequiredModules {
    [CmdletBinding()]
    param()
    
    begin {
        Write-Verbose "Checking required PowerShell modules..."
        $requiredModules = @('Az.Accounts', 'Az.SecurityInsights')
    }
    
    process {
        foreach ($module in $requiredModules) {
            try {
                if (!(Get-Module -ListAvailable -Name $module)) {
                    Write-Host "Installing module: $module" -ForegroundColor Yellow
                    Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                    Write-Host "Successfully installed module: $module" -ForegroundColor Green
                }
                
                Import-Module $module -Force -ErrorAction Stop
                Write-Verbose "Successfully imported module: $module"
            }
            catch {
                Write-Error "Failed to install or import module $module`: $($_.Exception.Message)"
                throw
            }
        }
    }
}
#endregion

#region Table and Connector Analysis
<#
.SYNOPSIS
    Extracts Log Analytics table names from KQL queries and maps them to data connectors.

.DESCRIPTION
    Parses KQL query text to identify table names and maps them to their corresponding
    data connectors using a comprehensive mapping table.

.PARAMETER Query
    The KQL query string to analyze.

.OUTPUTS
    Hashtable containing arrays of Tables and Connectors found in the query.
#>
function Get-TablesAndConnectors {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Query
    )
    
    begin {
        Write-Verbose "Analyzing KQL query for table and connector dependencies"
        
        # Comprehensive mapping of Log Analytics tables to their data connectors
        # This mapping covers the most common Sentinel data sources
        $tableToConnectorMap = @{
            # Security Events and Windows Logs
            'SecurityEvent'                        = 'SecurityEvents'
            'Event'                               = 'WindowsEvents'
            'WindowsFirewall'                     = 'WindowsFirewall'
            
            # Syslog and CEF
            'Syslog'                              = 'Syslog'
            'CommonSecurityLog'                   = 'CommonSecurityLog'
            
            # Azure Platform Logs
            'AzureActivity'                       = 'AzureActivity'
            'AzureDiagnostics'                    = 'AzureDiagnostics'
            'AzureFirewallApplicationRule'        = 'AzureFirewall'
            'AzureFirewallNetworkRule'            = 'AzureFirewall'
            'AzureFirewallDnsProxy'               = 'AzureFirewall'
            'AzureNetworkAnalytics_CL'            = 'AzureNetworkWatcher'
            
            # Azure Active Directory
            'SigninLogs'                          = 'AzureActiveDirectory'
            'AuditLogs'                           = 'AzureActiveDirectory'
            'AADSignInEventsBeta'                 = 'AzureActiveDirectory'
            'AADNonInteractiveUserSignInLogs'     = 'AzureActiveDirectory'
            'AADServicePrincipalSignInLogs'       = 'AzureActiveDirectory'
            'AADManagedIdentitySignInLogs'        = 'AzureActiveDirectory'
            'AADProvisioningLogs'                 = 'AzureActiveDirectory'
            
            # Microsoft 365 and Office
            'OfficeActivity'                      = 'Office365'
            'SharePointFileOperation'             = 'Office365SharePoint'
            'TeamsActivity'                       = 'MicrosoftTeams'
            'YammerActivity'                      = 'Yammer'
            'PowerBIActivity'                     = 'PowerBI'
            'DynamicsActivity'                    = 'Dynamics365'
            'ProjectActivity'                     = 'MicrosoftProject'
            
            # Microsoft Defender Products
            'SecurityAlert'                       = 'MicrosoftDefenderForCloud'
            'SecurityIncident'                    = 'MicrosoftDefenderForCloud'
            'DeviceEvents'                        = 'MicrosoftDefenderForEndpoint'
            'DeviceFileEvents'                    = 'MicrosoftDefenderForEndpoint'
            'DeviceImageLoadEvents'               = 'MicrosoftDefenderForEndpoint'
            'DeviceLogonEvents'                   = 'MicrosoftDefenderForEndpoint'
            'DeviceNetworkEvents'                 = 'MicrosoftDefenderForEndpoint'
            'DeviceNetworkInfo'                   = 'MicrosoftDefenderForEndpoint'
            'DeviceProcessEvents'                 = 'MicrosoftDefenderForEndpoint'
            'DeviceRegistryEvents'                = 'MicrosoftDefenderForEndpoint'
            'EmailEvents'                         = 'MicrosoftDefenderForOffice365'
            'EmailAttachmentInfo'                 = 'MicrosoftDefenderForOffice365'
            'EmailPostDeliveryEvents'             = 'MicrosoftDefenderForOffice365'
            'EmailUrlInfo'                        = 'MicrosoftDefenderForOffice365'
            'IdentityDirectoryEvents'             = 'MicrosoftDefenderForIdentity'
            'IdentityLogonEvents'                 = 'MicrosoftDefenderForIdentity'
            'IdentityQueryEvents'                 = 'MicrosoftDefenderForIdentity'
            'IdentityInfo'                        = 'MicrosoftDefenderForIdentity'
            
            # Cloud App Security
            'McasShadowItReporting'               = 'MicrosoftCloudAppSecurity'
            'CloudAppEvents'                      = 'MicrosoftCloudAppSecurity'
            
            # Threat Intelligence
            'ThreatIntelligenceIndicator'         = 'ThreatIntelligence'
            
            # UEBA and Behavior Analytics
            'BehaviorAnalytics'                   = 'UEBA'
            'UserAccessAnalytics'                 = 'UEBA'
            'UserPeerAnalytics'                   = 'UEBA'
            'Anomalies'                           = 'AnomalyAnalytics'
            
            # Infrastructure and Monitoring
            'Heartbeat'                           = 'MicrosoftMonitoringAgent'
            'VMConnection'                        = 'ServiceMap'
            'Perf'                                = 'Performance'
            'InsightsMetrics'                     = 'AzureMonitorAgent'
            
            # DNS and Network
            'DnsEvents'                           = 'DNS'
            'W3CIISLog'                           = 'IIS'
            
            # Cloud Platforms
            'AWSCloudTrail'                       = 'AmazonWebServicesCloudTrail'
            'AmazonWebServicesCloudTrail'         = 'AmazonWebServicesCloudTrail'
            'GCPAuditLogs'                        = 'GoogleCloudPlatformAuditLogs'
            
            # Storage and Key Vault
            'StorageBlobLogs'                     = 'AzureStorageAccount'
            'StorageFileLogs'                     = 'AzureStorageAccount'
            'StorageQueueLogs'                    = 'AzureStorageAccount'
            'StorageTableLogs'                    = 'AzureStorageAccount'
            'KeyVaultData'                        = 'AzureKeyVault'
            
            # Container and Kubernetes
            'ContainerLog'                        = 'ContainerInsights'
            'ContainerInventory'                  = 'ContainerInsights'
            'KubeEvents'                          = 'ContainerInsights'
            'KubePodInventory'                    = 'ContainerInsights'
            'KubeNodeInventory'                   = 'ContainerInsights'
            'KubeServices'                        = 'ContainerInsights'
            
            # Information Protection and Compliance
            'MicrosoftPurviewInformationProtection' = 'MicrosoftPurviewInformationProtection'
            'InformationProtectionLogs_CL'        = 'MicrosoftInformationProtection'
            
            # Log Analytics and Operations
            'LAQueryLogs'                         = 'LogAnalytics'
            'Usage'                               = 'LogAnalytics'
            'Operation'                           = 'LogAnalytics'
            
            # Microsoft Graph
            'MicrosoftGraphActivityLogs'          = 'MicrosoftGraphDataConnect'
            
            # Watchlists
            'Watchlist'                           = 'Watchlists'
        }
    }
    
    process {
        if ([string]::IsNullOrEmpty($Query)) {
            Write-Verbose "Query is empty, returning empty results"
            return @{
                Tables = @()
                Connectors = @()
            }
        }
        
        $foundTables = @()
        $foundConnectors = @()
        
        try {
            # Extract table names using regex pattern - look for table names followed by pipe
            # This pattern matches KQL syntax where table names are followed by the pipe operator
            $tablePattern = '\b([A-Za-z][A-Za-z0-9_]*(?:_CL)?)\s*\|'
            $matches = [regex]::Matches($Query, $tablePattern)
            
            Write-Verbose "Found $($matches.Count) potential table matches in query"
            
            foreach ($match in $matches) {
                $tableName = $match.Groups[1].Value
                
                # Only include tables that are in our known mapping or are custom logs (_CL suffix)
                if ($tableToConnectorMap.ContainsKey($tableName) -or $tableName.EndsWith('_CL')) {
                    if ($foundTables -notcontains $tableName) {
                        $foundTables += $tableName
                        Write-Verbose "Added table: $tableName"
                        
                        # Map table to its corresponding data connector
                        if ($tableToConnectorMap.ContainsKey($tableName)) {
                            $connector = $tableToConnectorMap[$tableName]
                            if ($foundConnectors -notcontains $connector) {
                                $foundConnectors += $connector
                                Write-Verbose "Added connector: $connector"
                            }
                        }
                        elseif ($tableName.EndsWith('_CL')) {
                            # Custom logs table
                            if ($foundConnectors -notcontains 'CustomLogs') {
                                $foundConnectors += 'CustomLogs'
                                Write-Verbose "Added custom logs connector for table: $tableName"
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Warning "Error parsing query for tables: $($_.Exception.Message)"
        }
        
        return @{
            Tables = $foundTables | Sort-Object
            Connectors = $foundConnectors | Sort-Object
        }
    }
}

<#
.SYNOPSIS
    Retrieves data connector requirements from Sentinel rule templates.

.DESCRIPTION
    Uses the Azure REST API to retrieve rule templates and extract their data connector
    requirements as defined in the Sentinel Content Hub.

.PARAMETER ResourceGroupName
    The resource group containing the Sentinel workspace.

.PARAMETER WorkspaceName
    The Log Analytics workspace name.

.OUTPUTS
    Hashtable mapping rule display names to their required data connectors.
#>
function Get-TemplateDataConnectors {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceName
    )
    
    begin {
        Write-Verbose "Retrieving template data connector information from Content Hub"
        $templateConnectors = @{}
    }
    
    process {
        try {
            # Get current Azure context and subscription information
            $context = Get-AzContext
            if (-not $context) {
                throw "No Azure context found. Please run Connect-AzAccount first."
            }
            
            $subscriptionId = $context.Subscription.Id
            
            # Get access token for Azure Resource Manager
            $accessToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
                $context.Account, 
                $context.Environment, 
                $context.Tenant.Id, 
                $null, 
                $null, 
                $null, 
                "https://management.azure.com/"
            ).AccessToken
            
            # Prepare REST API call headers
            $headers = @{
                'Authorization' = "Bearer $accessToken"
                'Content-Type'  = 'application/json'
            }
            
            # Build REST API URI for alert rule templates
            $uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRuleTemplates?api-version=2023-02-01"
            
            Write-Verbose "Making REST API call to retrieve rule templates"
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop
            
            if ($response -and $response.value) {
                Write-Host "Retrieved $($response.value.Count) rule templates from Content Hub" -ForegroundColor Green
                
                # Process each template to extract data connector requirements
                foreach ($template in $response.value) {
                    $connectors = @()
                    
                    if ($template.properties.requiredDataConnectors) {
                        foreach ($connector in $template.properties.requiredDataConnectors) {
                            if ($connector.connectorId) {
                                $connectors += $connector.connectorId
                            }
                        }
                    }
                    
                    if ($template.properties.displayName) {
                        $templateConnectors[$template.properties.displayName] = $connectors
                        Write-Verbose "Processed template: $($template.properties.displayName) with $($connectors.Count) connectors"
                    }
                }
            }
            else {
                Write-Warning "No rule templates found in the response"
            }
        }
        catch {
            Write-Warning "Could not retrieve template data connectors via REST API: $($_.Exception.Message)"
            Write-Verbose "Full error: $($_.Exception | Format-List * | Out-String)"
        }
    }
    
    end {
        Write-Verbose "Retrieved data connector information for $($templateConnectors.Count) rule templates"
        return $templateConnectors
    }
}
#endregion

#region Main Processing
<#
.SYNOPSIS
    Main execution function that orchestrates the entire analysis process.
#>
function Invoke-SentinelRulesAnalysis {
    [CmdletBinding()]
    param()
    
    begin {
        Write-Host "Starting Microsoft Sentinel Rules Data Connector Analysis..." -ForegroundColor Green
        Write-Host "Workspace: $WorkspaceName" -ForegroundColor Cyan
        Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor Cyan
        Write-Host "Subscription: $SubscriptionId" -ForegroundColor Cyan
        Write-Host ""
    }
    
    process {
        try {
            # Install and import required Azure PowerShell modules
            Write-Host "Checking required PowerShell modules..." -ForegroundColor Yellow
            Install-RequiredModules
            
            # Establish Azure connection
            Write-Host "Validating Azure connection..." -ForegroundColor Yellow
            $context = Get-AzContext
            if (-not $context) {
                Write-Host "No active Azure session found. Please authenticate..." -ForegroundColor Yellow
                Connect-AzAccount
                $context = Get-AzContext
            }
            
            Write-Host "Connected as: $($context.Account.Id)" -ForegroundColor Green
            
            # Set correct subscription context
            Write-Host "Setting subscription context to: $SubscriptionId" -ForegroundColor Yellow
            $null = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
            Write-Host "Subscription context set successfully" -ForegroundColor Green
            
            # Retrieve template data connector information from Content Hub
            Write-Host "Retrieving rule template data connector requirements..." -ForegroundColor Yellow
            $templateConnectors = Get-TemplateDataConnectors -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName
            
            # Get all analytical rules from the Sentinel workspace
            Write-Host "Retrieving analytical rules from Sentinel workspace..." -ForegroundColor Yellow
            $allRules = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction Stop
            
            Write-Host "Found $($allRules.Count) analytical rules in workspace" -ForegroundColor Cyan
            
            # Initialize results collection
            $results = @()
            $ruleCount = 0
            
            Write-Host "Processing analytical rules and analyzing dependencies..." -ForegroundColor Yellow
            
            # Process each rule to extract data connector and table requirements
            foreach ($rule in $allRules) {
                $ruleCount++
                
                # Display progress
                Write-Progress -Activity "Processing Analytical Rules" -Status "Analyzing rule $ruleCount of $($allRules.Count): $($rule.DisplayName)" -PercentComplete (($ruleCount / $allRules.Count) * 100)
                
                # Get template-based data connectors for this rule
                $templateDataConnectors = @()
                if ($templateConnectors.ContainsKey($rule.DisplayName)) {
                    $templateDataConnectors = $templateConnectors[$rule.DisplayName]
                    Write-Verbose "Found $($templateDataConnectors.Count) template connectors for rule: $($rule.DisplayName)"
                }
                
                # Analyze the rule's KQL query for table and connector dependencies
                $queryAnalysis = Get-TablesAndConnectors -Query $rule.Query
                
                # Combine template and query-based connector information
                $allConnectors = @()
                $allConnectors += $templateDataConnectors
                $allConnectors += $queryAnalysis.Connectors
                $allConnectors = $allConnectors | Sort-Object -Unique
                
                # Create analysis result object
                $result = [PSCustomObject]@{
                    RuleName                = $rule.DisplayName
                    Enabled                 = $rule.Enabled
                    Severity                = $rule.Severity
                    TemplateDataConnectors  = ($templateDataConnectors -join '; ')
                    AllRequiredConnectors   = ($allConnectors -join '; ')
                    RequiredTables          = ($queryAnalysis.Tables -join '; ')
                    ConnectorCount          = $allConnectors.Count
                    TableCount              = $queryAnalysis.Tables.Count
                    Description             = $rule.Description
                    RuleType                = $rule.Kind
                }
                
                $results += $result
                
                Write-Verbose "Processed rule: $($rule.DisplayName) - Tables: $($queryAnalysis.Tables.Count), Connectors: $($allConnectors.Count)"
            }
            
            Write-Progress -Activity "Processing Analytical Rules" -Completed
            
            # Export results to CSV file
            Write-Host "Exporting analysis results to CSV..." -ForegroundColor Yellow
            $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            
            Write-Host ""
            Write-Host "Analysis completed successfully!" -ForegroundColor Green
            Write-Host "Output file: $OutputPath" -ForegroundColor White
            
            # Generate and display summary statistics
            $enabledRules = ($results | Where-Object { $_.Enabled -eq $true }).Count
            $disabledRules = ($results | Where-Object { $_.Enabled -eq $false }).Count
            $rulesWithConnectors = ($results | Where-Object { $_.ConnectorCount -gt 0 }).Count
            $rulesWithTables = ($results | Where-Object { $_.TableCount -gt 0 }).Count
            $uniqueConnectors = ($results.AllRequiredConnectors -split '; ' | Where-Object { $_ -ne '' } | Sort-Object -Unique).Count
            $uniqueTables = ($results.RequiredTables -split '; ' | Where-Object { $_ -ne '' } | Sort-Object -Unique).Count
            
            Write-Host ""
            Write-Host "Analysis Summary:" -ForegroundColor Magenta
            Write-Host "  Total Rules Analyzed: $($results.Count)" -ForegroundColor White
            Write-Host "  Enabled Rules: $enabledRules" -ForegroundColor Green
            Write-Host "  Disabled Rules: $disabledRules" -ForegroundColor Yellow
            Write-Host "  Rules with Identified Data Connectors: $rulesWithConnectors" -ForegroundColor Green
            Write-Host "  Rules with Identified Tables: $rulesWithTables" -ForegroundColor Green
            Write-Host "  Unique Data Connectors Required: $uniqueConnectors" -ForegroundColor Cyan
            Write-Host "  Unique Tables Utilized: $uniqueTables" -ForegroundColor Cyan
            Write-Host ""
            
            # Display severity distribution
            $severityStats = $results | Group-Object Severity | Sort-Object Name
            Write-Host "Rule Severity Distribution:" -ForegroundColor Magenta
            foreach ($severity in $severityStats) {
                Write-Host "  $($severity.Name): $($severity.Count) rules" -ForegroundColor White
            }
        }
        catch {
            Write-Error "An error occurred during analysis: $($_.Exception.Message)"
            Write-Error "Stack Trace: $($_.Exception.StackTrace)"
            throw
        }
    }
}
#endregion

#region Script Execution
# Parameter validation
if (-not (Test-Path -Path (Split-Path $OutputPath -Parent))) {
    Write-Error "Output directory does not exist: $(Split-Path $OutputPath -Parent)"
    exit 1
}

# Execute main analysis
try {
    Invoke-SentinelRulesAnalysis
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}
#endregion

# End of script