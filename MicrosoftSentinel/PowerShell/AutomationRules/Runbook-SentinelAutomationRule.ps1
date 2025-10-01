<#
.SYNOPSIS
    Manages Microsoft Sentinel Automation rules using REST API for Azure Automation Runbooks.

.DESCRIPTION
    Lightweight script to enable or disable Sentinel Automation rules via REST API.
    Designed for Azure Automation runbooks with minimal output.

.PARAMETER SubscriptionId
    The Azure Subscription ID where Sentinel is deployed.

.PARAMETER ResourceGroupName
    The Resource Group containing the Sentinel workspace.

.PARAMETER WorkspaceName
    The name of the Log Analytics workspace where Sentinel is deployed.

.PARAMETER AutomationRuleName
    The Rule ID (GUID) or Display Name of the Automation rule to enable/disable.

.PARAMETER Action
    The action to perform: 'Enable' or 'Disable'.

.EXAMPLE
    .\Runbook-SentinelAutomationRule.ps1 -SubscriptionId "12345" -ResourceGroupName "rg-sentinel" `
        -WorkspaceName "law-sentinel" -AutomationRuleName "My Rule" -Action Disable

.NOTES
    FileName:    Runbook-SentinelAutomationRule.ps1
    Author:      Toby G
    Created:     2025-10-01
    Updated:     2025-10-01
    Version:     1.0
    
.LINK
    https://docs.microsoft.com/en-us/rest/api/securityinsights/automation-rules

.COMPONENT
    Requires Az.Accounts module
    Requires Managed Identity with Microsoft Sentinel Contributor role

.FUNCTIONALITY
    - Automatically detects if input is a GUID or Display Name
    - Connects using Managed Identity for Azure Automation
    - Enables or disables Sentinel Automation rules via REST API
    - Verifies the status change after update
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$WorkspaceName,
    
    [Parameter(Mandatory=$true)]
    [string]$AutomationRuleName,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet('Enable', 'Disable')]
    [string]$Action
)

# Function to check if string is a valid GUID
function Test-IsGuid {
    param([string]$Value)
    $guidRegex = '^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$'
    return $Value -match $guidRegex
}

# Connect to Azure using Managed Identity (for runbooks)
try {
    Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
}
catch {
    Write-Error "Failed to connect to Azure: $_"
    throw
}

# Get access token
try {
    $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
    if ([string]::IsNullOrEmpty($token)) {
        throw "Failed to obtain access token"
    }
}
catch {
    Write-Error "Failed to obtain access token: $_"
    throw
}

# Set API version and headers
$apiVersion = "2023-02-01"
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

$targetEnabled = ($Action -eq 'Enable')
$ruleId = $AutomationRuleName

# If not a GUID, search by display name
$isGuid = Test-IsGuid -Value $AutomationRuleName

if (-not $isGuid) {
    $listUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/automationRules?api-version=$apiVersion"
    
    try {
        $allRules = (Invoke-RestMethod -Uri $listUri -Method Get -Headers $headers -ErrorAction Stop).value
        $matchedRule = $allRules | Where-Object { $_.properties.displayName -ieq $AutomationRuleName } | Select-Object -First 1
        
        if (-not $matchedRule) {
            throw "Automation rule '$AutomationRuleName' not found"
        }
        
        $ruleId = $matchedRule.name
    }
    catch {
        Write-Error "Failed to find automation rule: $_"
        throw
    }
}

# Get current automation rule
$getUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/automationRules/$ruleId`?api-version=$apiVersion"

try {
    $response = Invoke-RestMethod -Uri $getUri -Method Get -Headers $headers -ErrorAction Stop
    $currentEnabled = $response.properties.triggeringLogic.isEnabled
    
    # Check if already in desired state
    if ($currentEnabled -eq $targetEnabled) {
        $state = if($targetEnabled){'enabled'}else{'disabled'}
        Write-Output "Rule is already $state. No action taken."
        return
    }
}
catch {
    Write-Error "Failed to retrieve automation rule: $_"
    throw
}

# Prepare update payload
$existingProperties = @{}
$response.properties.PSObject.Properties | ForEach-Object {
    $existingProperties[$_.Name] = $_.Value
}

$existingProperties['triggeringLogic'].isEnabled = $targetEnabled

$updateBody = @{
    etag = $response.etag
    properties = $existingProperties
}

$jsonBody = $updateBody | ConvertTo-Json -Depth 20

# Update the automation rule
$putUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/automationRules/$ruleId`?api-version=$apiVersion"

try {
    $updateResponse = Invoke-RestMethod -Uri $putUri -Method Put -Headers $headers -Body $jsonBody -ErrorAction Stop
    
    # Verify
    Start-Sleep -Seconds 2
    $verifyResponse = Invoke-RestMethod -Uri $getUri -Method Get -Headers $headers -ErrorAction Stop
    $verifiedEnabled = $verifyResponse.properties.triggeringLogic.isEnabled
    
    if ($verifiedEnabled -eq $targetEnabled) {
        $actionVerb = if($targetEnabled){'enabled'}else{'disabled'}
        Write-Output "Successfully $actionVerb automation rule: $($response.properties.displayName)"
    } else {
        throw "Status verification failed. Expected: $targetEnabled, Got: $verifiedEnabled"
    }
}
catch {
    Write-Error "Failed to update automation rule: $_"
    throw
}