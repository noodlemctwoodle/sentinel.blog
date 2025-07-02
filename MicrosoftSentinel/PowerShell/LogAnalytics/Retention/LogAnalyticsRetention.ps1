<#
.SYNOPSIS
    Azure Log Analytics Table Retention Management Script

.DESCRIPTION
    This script provides an interactive interface for managing retention policies on Log Analytics workspace tables.
    It utilises Out-ConsoleGridView for all user interactions, providing a modern console-based GUI experience.
    
    Key Features:
    - Interactive workspace selection
    - Plan-based table filtering (Analytics, Basic)
    - Multi-select table management
    - Retention period validation
    - Comprehensive logging and error handling
    - Real-time table existence validation utilising workspace Usage data

.PARAMETER TenantID
    The Azure Active Directory Tenant ID for authentication.
    This is required for establishing the Azure connection.

.PARAMETER TablePlan
    The default table plan type to work with. Valid values are 'Analytics' or 'Basic'.
    Defaults to 'Analytics' if not specified.
    Note: Users can override this during interactive filtering.

.PARAMETER RetentionDays
    The number of days to set for table retention.
    Must be between 4 and 4383 days (approximately 12 years).
    Different plan types have different valid ranges:
    - Analytics: 4-4383 days
    - Basic: 4-90 days

.EXAMPLE
    .\Set-LATableRetention.ps1 -TenantID "12345678-1234-1234-1234-123456789012" -RetentionDays 365
    
    Sets table retention to 1 year (365 days) utilising interactive selection for workspace and tables.

.EXAMPLE
    .\Set-LATableRetention.ps1 -TenantID "12345678-1234-1234-1234-123456789012" -RetentionDays 30 -TablePlan "Basic"
    
    Sets table retention to 30 days with a preference for Basic plan tables.

.NOTES
    Version:        2.0
    Author:         noodlemctwoodle
    Creation Date:  29/05/2025
    Purpose/Change: Modern interactive Log Analytics table retention management
    
    Prerequisites:
    - PowerShell 5.1 or later
    - Az.Accounts module
    - Az.OperationalInsights module  
    - Microsoft.PowerShell.ConsoleGuiTools module
    - Appropriate Azure RBAC permissions on Log Analytics workspaces
    
    Required Permissions:
    - Log Analytics Contributor or higher on target workspaces
    - Microsoft.OperationalInsights/workspaces/tables/write
    - Microsoft.OperationalInsights/workspaces/query/read
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Enter your Tenant Id")]
    [string] $TenantID,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Analytics', 'Basic')]
    [string] $TablePlan = 'Analytics',
    
    [Parameter(Mandatory = $true, HelpMessage = "Enter retention days (Analytics: 4-4383, Basic: 4-90)")]
    [ValidateRange(4, 4383)]
    [int] $RetentionDays
)

# Initialisation
# Initialise logging infrastructure with timestamp-based log file
$TimeStamp = Get-Date -Format yyyyMMdd_HHmmss 
$LogFileName = "LARetention_$TimeStamp.log"


# Logging Functions
<#
.SYNOPSIS
    Centralised logging function with multiple severity levels and colour coding.

.DESCRIPTION
    Provides consistent logging output to both console and log file.
    Console output utilises colour coding based on severity level for better readability.

.PARAMETER Message
    The message to log

.PARAMETER Severity
    The severity level: Information, Warning, or Error
#>
function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message, 
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Severity = 'Information'
    )
    
    # Create timestamped log entry
    $timestamp = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
    $logMessage = "[$timestamp] [$Severity] $Message"
    
    # Display to console with appropriate colour coding
    switch ($Severity) {
        'Information' { Write-Host $logMessage -ForegroundColor Green }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error' { Write-Host $logMessage -ForegroundColor Red }
    }
    
    # Append to log file for audit trail
    Add-Content -Path $LogFileName -Value $logMessage
}


# Data Retrieval Functions
<#
.SYNOPSIS
    Retrieves and validates Log Analytics tables that actually contain data in the specified workspace.

.DESCRIPTION
    This function performs a comprehensive table discovery process:
    1. Queries the workspace Usage table to identify tables with actual data
    2. Retrieves table configuration from the Azure Management API
    3. Cross-references both sources to ensure only real, accessible tables are returned
    4. Filters out system tables, phantom tables, and tables in invalid states

.PARAMETER Workspace
    The Log Analytics workspace object containing connection details

.OUTPUTS
    Array of custom objects representing valid tables with their properties:
    - TableName: The name of the table
    - TotalRetentionInDays: Current retention period in days
    - Plan: The table's pricing plan (Analytics, Basic, etc.)
    - SubscriptionId: Azure subscription ID
    - ResourceGroupName: Resource group containing the workspace
    - WorkspaceName: Name of the Log Analytics workspace
#>
function Get-AllWorkspaceTables {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [object]$Workspace
    )
    
    try {
        # Resource ID Parsing
        # Extract Azure resource components from the workspace resource ID
        $resourceId = $Workspace.ResourceId
        Write-Log "Processing workspace with ResourceId: $resourceId" -Severity Information
        
        # Use regex to parse the standard Azure resource ID format
        if ($resourceId -match '/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.OperationalInsights/workspaces/([^/]+)') {
            $subscriptionId = $matches[1]
            $resourceGroupName = $matches[2] 
            $workspaceName = $matches[3]
        } else {
            throw "Unable to parse workspace resource ID format: $resourceId"
        }
        
        Write-Log "Extracted resource details: Subscription=$subscriptionId, ResourceGroup=$resourceGroupName, Workspace=$workspaceName" -Severity Information
        

        # Usage Query for Table Discovery
        # Query the Usage table to identify tables that actually contain billable data
        # This prevents showing phantom tables that exist in the API but have no actual data
        Write-Log "Executing KQL query to discover tables with actual data..." -Severity Information
        
        $kqlQuery = @"
Usage
| where TimeGenerated > ago(30d)
| where IsBillable == true
| summarize DataGB = sum(Quantity) / 1000 by DataType
| where DataGB > 0
| project TableName = DataType
| sort by TableName asc
"@
        
        try {
            $tablesWithData = Invoke-AzOperationalInsightsQuery -WorkspaceId $Workspace.CustomerId -Query $kqlQuery -ErrorAction Stop
            $existingTableNames = $tablesWithData.Results | Select-Object -ExpandProperty TableName
            Write-Log "Usage query identified $($existingTableNames.Count) tables with billable data" -Severity Information
        }
        catch {
            Write-Log "Usage query failed, proceeding with API-only discovery: $($_.Exception.Message)" -Severity Warning
            $existingTableNames = @()
        }
        

        # API Table Configuration Retrieval
        # Retrieve table configuration from Azure Management API
        $baseUri = "https://management.azure.com"
        $uri = "$baseUri/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/tables?api-version=2021-12-01-preview"
        Write-Log "Retrieving table configurations from: $uri" -Severity Information
        
        # Prepare authentication headers
        $token = (Get-AzAccessToken).Token
        $headers = @{
            'Authorization' = "Bearer $token"
            'Content-Type' = 'application/json'
        }
        
        $response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers
        Write-Log "API returned $($response.value.Count) table definitions" -Severity Information
        

        # Table Validation and Filtering
        # Apply comprehensive filtering to ensure only valid, accessible tables are included
        $validTables = @()
        
        foreach ($table in $response.value) {
            # Skip tables missing essential properties
            if (-not $table.name -or -not $table.properties) {
                Write-Log "Excluding table without required name or properties" -Severity Warning
                continue
            }
            
            # Skip tables in transitional or failed states
            if ($table.properties.provisioningState -eq 'Deleting' -or $table.properties.provisioningState -eq 'Failed') {
                Write-Log "Excluding table '$($table.name)' in invalid state: $($table.properties.provisioningState)" -Severity Warning
                continue
            }
            
            # Cross-reference with Usage query results if available
            if ($existingTableNames.Count -gt 0 -and $table.name -notin $existingTableNames) {
                Write-Log "Excluding table '$($table.name)' - no data found in Usage query" -Severity Information
                continue
            }
            
            # Skip system tables without proper retention configuration
            if (-not $table.properties.PSObject.Properties['totalRetentionInDays'] -and 
                -not $table.properties.PSObject.Properties['retentionInDays'] -and
                $null -eq $table.properties.plan) {
                Write-Log "Excluding system table '$($table.name)' without retention configuration" -Severity Information
                continue
            }
            
            $validTables += $table
        }
        
        Write-Log "Filtered result: $($validTables.Count) valid tables identified" -Severity Information
        

        # Object Construction
        # Transform API response into standardised objects for consistent handling
        $allTables = $validTables | Select-Object @{
            Name = 'TableName'
            Expression = { $_.name }
        }, @{
            Name = 'TotalRetentionInDays'
            Expression = { 
                # Handle different retention property names and provide reasonable defaults
                if ($_.properties.totalRetentionInDays) { 
                    $_.properties.totalRetentionInDays 
                } elseif ($_.properties.retentionInDays) {
                    $_.properties.retentionInDays
                } else { 
                    90  # Standard default retention for tables without explicit configuration
                }
            }
        }, @{
            Name = 'Plan'
            Expression = { 
                # Default to Analytics plan for tables without explicit plan assignment
                if ($_.properties.plan) { $_.properties.plan } else { "Analytics" } 
            }
        }, @{
            Name = 'SubscriptionId'
            Expression = { $subscriptionId }
        }, @{
            Name = 'ResourceGroupName'
            Expression = { $resourceGroupName }
        }, @{
            Name = 'WorkspaceName'
            Expression = { $workspaceName }
        }
        
        Write-Log "Successfully processed $($allTables.Count) tables for workspace '$workspaceName'" -Severity Information
        

        # Debug Output
        # Provide detailed logging of discovered tables for troubleshooting
        Write-Log "Table inventory for workspace '$workspaceName':" -Severity Information
        foreach ($table in $allTables) {
            Write-Log "  └─ $($table.TableName): Plan=$($table.Plan), Retention=$($table.TotalRetentionInDays) days" -Severity Information
        }
        
        
        return $allTables
        
    }
    catch {
        Write-Log "Critical error in table discovery process: $($_.Exception.Message)" -Severity Error
        Write-Log "Full exception details: $($_.Exception)" -Severity Error
        throw
    }
}

<#
.SYNOPSIS
    Filters the complete table list to only include tables matching the specified plan type.

.DESCRIPTION
    Applies case-insensitive filtering to return only tables with the specified pricing plan.
    Also validates that returned tables have valid retention periods greater than zero.

.PARAMETER AllTables
    Array of table objects to filter

.PARAMETER Plan
    The plan type to filter by (Analytics, Basic, etc.)

.OUTPUTS
    Array of table objects matching the specified plan criteria
#>
function Get-TablesByPlan {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [array]$AllTables,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Plan
    )
    
    Write-Log "Applying plan filter: '$Plan'" -Severity Information
    
    # Apply case-insensitive plan filtering with retention validation
    $filteredTables = $AllTables | Where-Object { 
        $_.Plan -ieq $Plan -and $_.TotalRetentionInDays -gt 0
    }
    
    if (-not $filteredTables) {
        Write-Log "No tables found matching plan '$Plan'" -Severity Warning
        
        # Provide helpful information about available plans
        $availablePlans = ($AllTables | Where-Object { $_.Plan -ne "Not Set" } | 
                          Select-Object -ExpandProperty Plan | Sort-Object -Unique) -join ', '
        Write-Log "Available plans in workspace: $availablePlans" -Severity Information
        return @()
    }
    
    Write-Log "Plan filter '$Plan' matched $($filteredTables.Count) tables" -Severity Information
    return $filteredTables
}


# User Interface Functions
<#
.SYNOPSIS
    Provides interactive table selection utilising Out-ConsoleGridView with optional plan-based filtering.

.DESCRIPTION
    Displays tables in a modern console grid interface allowing users to select multiple tables.
    Includes plan information and current retention settings for informed decision making.
    Supports both filtered and unfiltered views based on user preference.

.PARAMETER AllTables
    Complete array of available table objects

.PARAMETER FilterByPlan
    Optional plan type to pre-filter the displayed tables

.OUTPUTS
    Array of user-selected table objects
#>
function Select-Tables {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [array]$AllTables,
        
        [Parameter(Mandatory = $false)]
        [string]$FilterByPlan = $null
    )

    # Validate input data
    if ($AllTables.Count -eq 0) {
        throw "No tables available for selection. Verify workspace contains accessible tables."
    }

    # Table Filtering Logic
    # Apply optional plan-based filtering with fallback to full list
    $tablesToShow = if ($FilterByPlan) {
        $filtered = $AllTables | Where-Object { $_.Plan -ieq $FilterByPlan -and $_.TotalRetentionInDays -gt 0 }
        if (-not $filtered) {
            # Provide user feedback when filter returns no results
            Write-Host "No tables found with plan: $FilterByPlan" -ForegroundColor Yellow
            $availablePlans = ($AllTables | Where-Object { $_.Plan -ne 'Not Set' } | 
                              Select-Object -ExpandProperty Plan | Sort-Object -Unique) -join ', '
            Write-Host "Available plans: $availablePlans" -ForegroundColor Yellow
            Write-Host "`nDisplaying all available tables instead..." -ForegroundColor Yellow
            $AllTables
        } else {
            $filtered
        }
    } else {
        $AllTables
    }
    

    # Display Data Preparation
    # Format table data for optimal display in the grid view
    $tableDetails = $tablesToShow | Select-Object @{
        Name = 'TableName'
        Expression = { $_.TableName }
    }, @{
        Name = 'Plan'
        Expression = { $_.Plan }
    }, @{
        Name = 'Current Retention'
        Expression = { "$($_.TotalRetentionInDays) days" }
    }
    

    # Interactive Selection
    # Present user interface and capture selections
    $title = if ($FilterByPlan) { 
        "Select Tables to Update ($FilterByPlan Plan)" 
    } else { 
        "Select Tables to Update (All Plans)" 
    }
    
    Write-Log "Presenting table selection interface with $($tablesToShow.Count) options" -Severity Information
    $selected = $tableDetails | Out-ConsoleGridView -Title $title
    
    # Validate user selection
    if ($null -eq $selected -or $selected.Count -eq 0) {
        throw "Operation cancelled - no tables selected by user"
    }
    
    Write-Log "User selected $($selected.Count) tables for processing" -Severity Information
    
    
    # Return original table objects corresponding to user selections
    return $AllTables | Where-Object { $_.TableName -in $selected.TableName }
}

<#
.SYNOPSIS
    Provides interactive workspace selection utilising Out-ConsoleGridView with single-selection enforcement.

.DESCRIPTION
    Displays available Log Analytics workspaces in a console grid interface.
    Shows workspace name, resource group, and location for informed selection.
    Enforces single selection to ensure clear workspace targeting.

.PARAMETER Workspaces
    Array of Log Analytics workspace objects from Get-AzOperationalInsightsWorkspace

.OUTPUTS
    Single selected workspace object
#>
function Select-Workspace {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [array]$Workspaces
    )

    # Validate input data
    if ($Workspaces.Count -eq 0) {
        throw "No Log Analytics workspaces available. Verify Azure permissions and workspace existence."
    }

    # Display Data Preparation  
    # Format workspace data for clear identification in the selection interface
    $workspaceDetails = $Workspaces | Select-Object @{
        Name = 'Name'
        Expression = { $_.Name }
    }, @{
        Name = 'ResourceGroup'
        Expression = { $_.ResourceGroupName }
    }, @{
        Name = 'Location'
        Expression = { $_.Location }
    }
    

    # Interactive Selection
    # Present single-selection interface for workspace choice
    Write-Log "Presenting workspace selection interface with $($Workspaces.Count) options" -Severity Information
    $selected = $workspaceDetails | Out-ConsoleGridView -Title "Select a Log Analytics Workspace" -OutputMode Single
    
    # Validate selection
    if ($null -eq $selected) {
        throw "Operation cancelled - no workspace selected by user"
    }
    
    Write-Log "User selected workspace: '$($selected.Name)'" -Severity Information
    
    
    # Return the original workspace object corresponding to the selection
    return $Workspaces | Where-Object { $_.Name -eq $selected.Name }
}


# Main Execution Block
<#
.SYNOPSIS
    Main script execution flow with comprehensive error handling and user interaction.

.DESCRIPTION
    Orchestrates the complete retention management workflow including:
    - Azure authentication and connection establishment
    - Interactive workspace selection
    - Table discovery and filtering
    - User-driven table selection and confirmation
    - Batch retention updates with progress tracking
    - Summary reporting
#>
try {
    # Prerequisites and Environment Setup
    Write-Log "Initialising Log Analytics Table Retention Management Script v2.0" -Severity Information
    
    # Verify and install required PowerShell modules
    $requiredModules = @('Az.Accounts', 'Az.OperationalInsights', 'Microsoft.PowerShell.ConsoleGuiTools')
    Write-Log "Checking required PowerShell modules: $($requiredModules -join ', ')" -Severity Information
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Log "Installing missing module: $module" -Severity Warning
            Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
        }
        Import-Module $module -Force
        Write-Log "Module '$module' loaded successfully" -Severity Information
    }
    
    # Configure environment to suppress Azure PowerShell breaking change warnings
    Set-Item -Path Env:SuppressAzurePowerShellBreakingChangeWarnings -Value $true
    $WarningPreference = 'SilentlyContinue'
    Write-Log "Environment configured for clean execution" -Severity Information  
    
    # Azure Authentication and Connection
    Write-Log "Initiating Azure authentication for Tenant ID: $TenantID" -Severity Information
    Write-Log "Note: Azure may display native subscription selection interface if multiple subscriptions are available" -Severity Information
    
    # Establish Azure connection
    Connect-AzAccount -TenantId $TenantID -ErrorAction Stop
    
    # Verify successful authentication and retrieve context
    $currentContext = Get-AzContext
    if ($currentContext) {
        Write-Log "Azure authentication successful" -Severity Information
        Write-Log "Active subscription: '$($currentContext.Subscription.Name)' ($($currentContext.Subscription.Id))" -Severity Information
    } else {
        throw "Failed to establish Azure PowerShell context after authentication"
    }
    
    # Workspace Discovery and Selection
    Write-Log "Discovering available Log Analytics workspaces..." -Severity Information
    $workspaces = Get-AzOperationalInsightsWorkspace | Where-Object { $_.ProvisioningState -eq "Succeeded" }

    if (-not $workspaces) {
        throw "No accessible Log Analytics workspaces found. Verify Azure permissions and workspace existence."
    }
    
    Write-Log "Found $($workspaces.Count) accessible workspace(s)" -Severity Information

    # Interactive workspace selection
    $workspace = Select-Workspace -Workspaces $workspaces
    
    if (-not $workspace) {
        throw "Workspace selection failed - operation cannot continue"
    }
    
    Write-Log "Target workspace selected: '$($workspace.Name)' in resource group '$($workspace.ResourceGroupName)'" -Severity Information
    
    
    # Table Discovery and Analysis
    Write-Log "Beginning comprehensive table discovery for workspace '$($workspace.Name)'..." -Severity Information
    $allTables = Get-AllWorkspaceTables -Workspace $workspace

    if (-not $allTables -or $allTables.Count -eq 0) {
        Write-Log "No manageable tables found in workspace '$($workspace.Name)'" -Severity Warning
        Write-Log "This may indicate: no data ingestion, insufficient permissions, or workspace configuration issues" -Severity Warning
        return
    }

    Write-Host "`nWorkspace Analysis Complete: $($allTables.Count) manageable tables discovered" -ForegroundColor Green
    
    # Generate plan-based summary for user awareness
    $planSummary = $allTables | Where-Object { $_.Plan -ne "Not Set" } | Group-Object Plan | Select-Object Name, Count
    if ($planSummary) {
        Write-Host "`nTable Distribution by Pricing Plan:" -ForegroundColor Cyan
        foreach ($plan in $planSummary) {
            Write-Host "  ├─ $($plan.Name): $($plan.Count) tables" -ForegroundColor Yellow
        }
        Write-Host "" # Add spacing for readability
    }
    
    # User-Driven Filtering and Selection
    # Use the TablePlan parameter to determine filtering approach
    Write-Log "Using TablePlan parameter: '$TablePlan' for table filtering" -Severity Information
    
    # Apply filtering based on the TablePlan parameter
    if ($TablePlan -eq "Analytics" -or $TablePlan -eq "Basic") {
        Write-Log "Applying plan filter: '$TablePlan'" -Severity Information
        $planTables = Get-TablesByPlan -AllTables $allTables -Plan $TablePlan
        
        if (-not $planTables -or $planTables.Count -eq 0) {
            Write-Log "No tables found matching plan '$TablePlan' - operation terminated" -Severity Warning
            return
        }
        
        $selectedTables = Select-Tables -AllTables $planTables -FilterByPlan $TablePlan
    } else {
        # Fallback to showing all tables if TablePlan is somehow invalid
        Write-Log "Presenting all available tables for selection" -Severity Information
        $selectedTables = Select-Tables -AllTables $allTables
    }
    
    Write-Log "Table selection complete: $($selectedTables.Count) tables chosen for retention update" -Severity Information

    # Update Confirmation and Validation
    Write-Host "`nPreparing retention update confirmation interface..." -ForegroundColor Yellow
    
    # Prepare comprehensive confirmation data showing before/after state
    $confirmationData = $selectedTables | Select-Object @{
        Name = 'TableName'
        Expression = { $_.TableName }
    }, @{
        Name = 'CurrentRetention'
        Expression = { "$($_.TotalRetentionInDays) days" }
    }, @{
        Name = 'NewRetention'
        Expression = { "$RetentionDays days" }
    }, @{
        Name = 'Plan'
        Expression = { $_.Plan }
    }
    
    # Present final confirmation interface
    Write-Log "Presenting update confirmation interface for final user approval" -Severity Information
    $confirmSelection = $confirmationData | Out-ConsoleGridView -Title "Confirm Table Updates - Select tables to proceed (ESC to cancel)"
    
    # Validate final confirmation
    if ($null -eq $confirmSelection -or $confirmSelection.Count -eq 0) {
        Write-Log "Operation cancelled by user during final confirmation" -Severity Warning
        return
    }
    
    # Determine final table set for updates
    $confirmedTables = $selectedTables | Where-Object { $_.TableName -in $confirmSelection.TableName }
    Write-Log "Final confirmation: $($confirmedTables.Count) tables approved for retention update to $RetentionDays days" -Severity Information
    
    # Batch Retention Updates
    Write-Log "Beginning batch retention updates..." -Severity Information
    $successCount = 0
    $errorCount = 0
    
    foreach ($table in $confirmedTables) {
        try {
            # Construct Azure Management API endpoint for table configuration
            $uri = "https://management.azure.com/subscriptions/$($table.SubscriptionId)/resourcegroups/$($table.ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($table.WorkspaceName)/tables/$($table.TableName)?api-version=2021-12-01-preview"
            
            # Prepare update payload
            $body = @{
                properties = @{
                    plan = $TablePlan
                    totalRetentionInDays = $RetentionDays
                }
            } | ConvertTo-Json
            
            # Prepare authenticated request headers
            $token = (Get-AzAccessToken).Token
            $headers = @{
                'Authorization' = "Bearer $token"
                'Content-Type' = 'application/json'
            }
            
            # Execute retention update via REST API
            Invoke-RestMethod -Uri $uri -Method PUT -Headers $headers -Body $body | Out-Null
            Write-Log "✓ Successfully updated '$($table.TableName)': Plan=$TablePlan, Retention=$RetentionDays days" -Severity Information
            $successCount++
        }
        catch {
            Write-Log "✗ Failed to update '$($table.TableName)': $($_.Exception.Message)" -Severity Error
            $errorCount++
        }
    }   
    
    # Execution Summary
    Write-Log "Batch retention update completed - Summary: $successCount successful, $errorCount failed out of $($confirmedTables.Count) tables" -Severity Information
    
    # Provide additional guidance if there were failures
    if ($errorCount -gt 0) {
        Write-Log "Review error messages above for failed updates. Common causes include insufficient permissions or invalid retention values for specific table types." -Severity Warning
    }
    
    Write-Log "Log Analytics Table Retention Management Script execution completed successfully" -Severity Information
    Write-Log "Detailed execution log saved to: $LogFileName" -Severity Information   
    
}
catch {
    # Comprehensive error handling for any unhandled exceptions
    Write-Log "Critical script execution failure: $($_.Exception.Message)" -Severity Error
    Write-Log "Full error details: $($_.Exception)" -Severity Error
    Write-Log "Script terminated due to unrecoverable error - review log file: $LogFileName" -Severity Error
    throw
}
