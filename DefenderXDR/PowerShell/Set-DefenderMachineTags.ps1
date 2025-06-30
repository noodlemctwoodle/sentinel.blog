<#
.SYNOPSIS
    Bulk tag machines in Microsoft Defender XDR using a CSV file.

.DESCRIPTION
    This script reads machine names and tags from a CSV file and applies them to machines 
    in Microsoft Defender for Endpoint using the Microsoft Graph Security API.
    
    The CSV file must contain 'MachineName' and 'Tag' columns.

.PARAMETER CsvPath
    Path to the CSV file containing machine names and tags.

.PARAMETER TenantId
    Entra ID  tenant ID where the Defender for Endpoint instance is located.

.PARAMETER ClientId
    Application (client) ID of the Entra ID app registration with appropriate permissions.

.PARAMETER ClientSecret
    Client secret for the Entra ID app registration.

.EXAMPLE
    .\Set-DefenderMachineTags.ps1 -CsvPath "machines.csv" -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ClientSecret "your-secret"

.NOTES
    File Name      : Set-DefenderMachineTags.ps1
    Author         : Toby G
    Prerequisite   : Entra ID app registration with Machine.ReadWrite.All (Application) permissions
    
    Required CSV Format:
    MachineName,Tag
    DESKTOP-ABC123,Development
    SERVER-XYZ789,Production
    
    Entra ID  App Registration Requirements:
    - Application permissions: Machine.ReadWrite.All for Microsoft Defender for Endpoint
    - Admin consent granted
    - Client secret configured

.LINK
    https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/api-hello-world
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to CSV file with MachineName and Tag columns")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $true, HelpMessage = "Entra ID tenant ID")]
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string]$TenantId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Entra ID application client ID")]
    [ValidatePattern('^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
    [string]$ClientId,
    
    [Parameter(Mandatory = $true, HelpMessage = "Entra ID application client secret")]
    [ValidateNotNullOrEmpty()]
    [string]$ClientSecret
)

#Requires -Version 5.1

# Script configuration
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# API endpoints
$script:TokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$script:DefenderApiBase = "https://api.securitycenter.microsoft.com/api"

#region Helper Functions

function Write-LogMessage {
    <#
    .SYNOPSIS
        Writes formatted log messages with timestamps and color coding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] $Message"
    
    switch ($Level) {
        'Info'    { Write-Host $logMessage -ForegroundColor Cyan }
        'Warning' { Write-Warning $logMessage }
        'Error'   { Write-Error $logMessage }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        'Debug'   { Write-Host $logMessage -ForegroundColor Gray }
    }
}

function Get-DefenderAccessToken {
    <#
    .SYNOPSIS
        Obtains an access token for Microsoft Defender for Endpoint API using client credentials flow.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientSecret
    )
    
    try {
        Write-LogMessage "Authenticating with Microsoft Defender for Endpoint API..." -Level Info
        
        $tokenBody = @{
            grant_type    = 'client_credentials'
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = 'https://api.securitycenter.microsoft.com/.default'
        }
        
        $tokenParams = @{
            Uri         = $script:TokenEndpoint
            Method      = 'POST'
            Body        = $tokenBody
            ContentType = 'application/x-www-form-urlencoded'
        }
        
        $response = Invoke-RestMethod @tokenParams
        Write-LogMessage "Authentication successful" -Level Success
        
        return $response.access_token
    }
    catch {
        Write-LogMessage "Authentication failed: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-DefenderMachineId {
    <#
    .SYNOPSIS
        Retrieves the machine ID for a given machine name from Defender for Endpoint.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MachineName,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )
    
    try {
        Write-LogMessage "Searching for machine: $MachineName" -Level Debug
        
        $filterParams = @{
            '$filter' = "computerDnsName eq '$MachineName'"
        }
        
        $requestParams = @{
            Uri     = "$script:DefenderApiBase/machines"
            Headers = $Headers
            Body    = $filterParams
            Method  = 'GET'
        }
        
        $response = Invoke-RestMethod @requestParams
        
        if ($response.value.Count -gt 0) {
            $machine = $response.value[0]
            Write-LogMessage "Found machine: $($machine.computerDnsName) (ID: $($machine.id))" -Level Debug
            return $machine.id
        }
        else {
            Write-LogMessage "Machine '$MachineName' not found in Defender for Endpoint" -Level Warning
            return $null
        }
    }
    catch {
        Write-LogMessage "Failed to retrieve machine ID for '$MachineName': $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Add-DefenderMachineTag {
    <#
    .SYNOPSIS
        Adds a tag to a machine in Microsoft Defender for Endpoint.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MachineId,
        
        [Parameter(Mandatory = $true)]
        [string]$Tag,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )
    
    try {
        $tagBody = @{
            Value  = $Tag
            Action = 'Add'
        } | ConvertTo-Json -Depth 2
        
        $requestParams = @{
            Uri         = "$script:DefenderApiBase/machines/$MachineId/tags"
            Headers     = $Headers
            Body        = $tagBody
            Method      = 'POST'
            ContentType = 'application/json'
        }
        
        $null = Invoke-RestMethod @requestParams
        return $true
    }
    catch {
        Write-LogMessage "Failed to add tag '$Tag' to machine ID '$MachineId': $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Test-CsvFormat {
    <#
    .SYNOPSIS
        Validates that the CSV file has the required columns.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$CsvData
    )
    
    $requiredColumns = @('MachineName', 'Tag')
    $csvColumns = $CsvData[0].PSObject.Properties.Name
    
    foreach ($column in $requiredColumns) {
        if ($column -notin $csvColumns) {
            throw "CSV file must contain '$column' column. Found columns: $($csvColumns -join ', ')"
        }
    }
    
    # Check for empty values
    $emptyRows = $CsvData | Where-Object { 
        [string]::IsNullOrWhiteSpace($_.MachineName) -or [string]::IsNullOrWhiteSpace($_.Tag) 
    }
    
    if ($emptyRows.Count -gt 0) {
        Write-LogMessage "Found $($emptyRows.Count) rows with empty MachineName or Tag values - these will be skipped" -Level Warning
    }
}

#endregion

#region Main Script Logic

try {
    Write-LogMessage "Starting Microsoft Defender XDR machine tagging process" -Level Info
    Write-LogMessage "Script version: 1.0" -Level Debug
    
    # Import and validate CSV data
    Write-LogMessage "Loading CSV file: $CsvPath" -Level Info
    $machineData = Import-Csv -Path $CsvPath
    
    if ($machineData.Count -eq 0) {
        throw "CSV file is empty or invalid"
    }
    
    Write-LogMessage "Loaded $($machineData.Count) records from CSV" -Level Success
    
    # Validate CSV format
    Test-CsvFormat -CsvData $machineData
    
    # Filter out empty rows
    $validMachineData = $machineData | Where-Object { 
        -not [string]::IsNullOrWhiteSpace($_.MachineName) -and -not [string]::IsNullOrWhiteSpace($_.Tag) 
    }
    
    Write-LogMessage "Processing $($validMachineData.Count) valid machine records" -Level Info
    
    # Authenticate and get access token
    $accessToken = Get-DefenderAccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    
    # Prepare request headers
    $headers = @{
        'Authorization' = "Bearer $accessToken"
        'Content-Type'  = 'application/json'
    }
    
    # Process each machine
    $results = @{
        Successful = 0
        Failed     = 0
        Details    = @()
    }
    
    foreach ($machine in $validMachineData) {
        $machineName = $machine.MachineName.Trim()
        $tag = $machine.Tag.Trim()
        
        Write-LogMessage "Processing: $machineName -> $tag" -Level Info
        
        # Get machine ID
        $machineId = Get-DefenderMachineId -MachineName $machineName -Headers $headers
        
        if ($machineId) {
            # Add tag to machine
            $success = Add-DefenderMachineTag -MachineId $machineId -Tag $tag -Headers $headers
            
            if ($success) {
                Write-LogMessage "Successfully added tag '$tag' to '$machineName'" -Level Success
                $results.Successful++
                $results.Details += [PSCustomObject]@{
                    MachineName = $machineName
                    Tag         = $tag
                    Status      = 'Success'
                    Message     = 'Tag added successfully'
                }
            }
            else {
                $results.Failed++
                $results.Details += [PSCustomObject]@{
                    MachineName = $machineName
                    Tag         = $tag
                    Status      = 'Failed'
                    Message     = 'Failed to add tag'
                }
            }
        }
        else {
            $results.Failed++
            $results.Details += [PSCustomObject]@{
                MachineName = $machineName
                Tag         = $tag
                Status      = 'Failed'
                Message     = 'Machine not found'
            }
        }
        
        # Rate limiting - avoid overwhelming the API
        Start-Sleep -Milliseconds 500
    }
    
    # Display summary
    Write-LogMessage "Tagging operation completed" -Level Success
    Write-LogMessage "Successful operations: $($results.Successful)" -Level Success
    Write-LogMessage "Failed operations: $($results.Failed)" -Level $(if ($results.Failed -gt 0) { 'Warning' } else { 'Success' })
    
    # Export detailed results
    $resultsPath = Join-Path (Split-Path $CsvPath -Parent) "DefenderTagging_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $results.Details | Export-Csv -Path $resultsPath -NoTypeInformation
    Write-LogMessage "Detailed results exported to: $resultsPath" -Level Info
}
catch {
    Write-LogMessage "Script execution failed: $($_.Exception.Message)" -Level Error
    exit 1
}
finally {
    Write-LogMessage "Script execution completed" -Level Info
}

#endregion