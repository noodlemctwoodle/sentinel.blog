$WarningPreference = 'SilentlyContinue'

function Write-Log {
    param(
        [string]$Message
    )
    $logFilePath = "$PSScriptRoot\AutomationRules\logFile.txt"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File $logFilePath -Append
}

$jsonFilePath = "$PSScriptRoot\AutomationRules\"
$tenantId = "Tenant Id Here"

$currentContext = Get-AzContext
if ($currentContext -and $currentContext.Tenant.Id -eq $tenantId) {
    Write-Host "Already authenticated to tenant $tenantId"
} else {
    Write-Host "Not authenticated to tenant $tenantId. Connecting..."
    Connect-AzAccount -Tenant $tenantId
}

Write-Host "Loading Subscriptions, please wait..." -ForegroundColor Green
Write-Log "Loading Subscriptions"
Start-Sleep -Seconds 5

function Get-AuthToken {
    
    Write-Log "Getting Authentication Token..."

    $azureProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azureProfile)
    $context = Get-AzContext
    return $profileClient.AcquireAccessToken($context.Subscription.TenantId).AccessToken
}

function Get-MicrosoftSentinelResources {
    
    Write-Log "Getting Microsoft Sentinel Resources..."

    $subscriptions = Get-AzSubscription | Select-Object -Property Name, Id
    $selectedSubscription = $subscriptions | Out-ConsoleGridView -Title "Select your subscription" -OutputMode Single
    Set-AzContext -SubscriptionId $selectedSubscription.Id
    Write-Log "Selected Subscription ID: $($selectedSubscription.Id)"

    $resourceGroups = Get-AzResourceGroup | Select-Object -Property ResourceGroupName
    $selectedResourceGroup = $resourceGroups | Out-ConsoleGridView -Title "Select your resource group" -OutputMode Single
    Write-Log "Selected Resource Group: $($selectedResourceGroup.ResourceGroupName)"

    $workspaces = Get-AzOperationalInsightsWorkspace -ResourceGroupName $selectedResourceGroup.ResourceGroupName | Select-Object -Property Name
    $selectedWorkspace = $workspaces | Out-ConsoleGridView -Title "Select your Log Analytics Workspace" -OutputMode Single
    Write-Log "Selected Workspace: $($selectedWorkspace.Name)"

    return @{
        SubscriptionId = $selectedSubscription.Id
        ResourceGroupName = $selectedResourceGroup.ResourceGroupName
        WorkspaceName = $selectedWorkspace.Name
    }
}

function Get-MicrosoftSentinelAutomationRules {
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$WorkspaceName
    )

    Write-Log "Retrieving Microsoft Sentinel Automation Rules for Workspace: $WorkspaceName"

    $authHeader = @{
        'Content-Type' = 'application/json'
        'Authorization' = 'Bearer ' + (Get-AuthToken)
    }

    $uri = "https://management.azure.com/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($WorkspaceName)/providers/Microsoft.SecurityInsights/automationRules?api-version=2023-11-01-preview"

    try {
        $results = (Invoke-RestMethod -Method Get -Uri $uri -Headers $authHeader).value
        Write-Log "Automation rules retrieved successfully."
        return $results
    } catch {
        Write-Log "Error retrieving automation rules: $_"
    }
}

function Set-MicrosoftSentinelAutomationRules {
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$WorkspaceName,
        [string]$JsonString
    )

    Write-Log "Setting a new Microsoft Sentinel Automation Rule in Workspace: $WorkspaceName"

    $authHeader = @{
        'Content-Type' = 'application/json'
        'Authorization' = 'Bearer ' + (Get-AuthToken)
    }

    $guid = (New-Guid).Guid
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/automationRules/$($guid)?api-version=2023-11-01-preview"

    try {
        Write-Log  "URI: $uri"
        Write-Log  "Debug: Rule JSON - $JsonString"
        $result = Invoke-RestMethod -Uri $uri -Method PUT -Body $JsonString -Headers $authHeader
        Write-Log  "New rule deployed. Rule ID: $($result.name)"
        return $result
    } catch {
        Write-Log "Error deploying automation rule: $_"
    }
}

function Export-AutomationRulesToJson {
    param(
        [Parameter(Mandatory = $true)]
        [Object[]]$AutomationRules,

        [Parameter(Mandatory = $true)]
        [string]$ExportPath
    )

    foreach ($rule in $AutomationRules) {
        $ruleName = $rule.properties.displayName -replace "\s+", "_"
        $filePath = Join-Path -Path $ExportPath -ChildPath ("$ruleName.json")

        try {
            $rule | ConvertTo-Json -Depth 100 | Set-Content -Path $filePath
            Write-Log "Rule '$ruleName' exported successfully to $filePath"
        } catch {
            Write-Log "Error exporting rule '$ruleName' to JSON: $_"
        }
    }
}

Clear-Host

Write-Log "Starting main execution..."

$sentinelResources = Get-MicrosoftSentinelResources
$subscriptionId = $sentinelResources.SubscriptionId
$resourceGroup = $sentinelResources.ResourceGroupName
$workspaceName = $sentinelResources.WorkspaceName

Write-Log "Selected Resources for Retrieving Rules: SubscriptionId: $subscriptionId, ResourceGroup: $resourceGroup, Workspace: $workspaceName"

$automationRules = Get-MicrosoftSentinelAutomationRules -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroup -WorkspaceName $workspaceName

$createOptions = @("yes", "no") | Select-Object @{Name = "Response"; Expression = {$_}}
$exportToJsonResponse = $createOptions | Out-ConsoleGridView -Title "Do you want to export the automation rules to JSON?" -OutputMode Single

if ($exportToJsonResponse.Response -eq "yes") {
    Export-AutomationRulesToJson -AutomationRules $automationRules -ExportPath $jsonFilePath
} else {
    Write-Log "Storing retrieved automation rules in variable for later use."
    $exportedRules = $automationRules
}

Write-Log "Setting a new Microsoft Sentinel Automation Rule..."

$setRuleOptions = @("selection", "all", "cancel") | Select-Object @{Name = "Response"; Expression = {$_}}
$setRuleResponse = $setRuleOptions | Out-ConsoleGridView -Title "Do you want to deploy a single rule, multiple rules, all stored rules, or cancel?" -OutputMode Single

switch ($setRuleResponse.Response) {
    "selection" {
        $newSentinelResources = Get-MicrosoftSentinelResources
        $newSubscriptionId = $newSentinelResources.SubscriptionId
        $newResourceGroup = $newSentinelResources.ResourceGroupName
        $newWorkspaceName = $newSentinelResources.WorkspaceName

        $selectedRulesDisplayNames = $exportedRules | 
            Select-Object @{Name='DisplayName'; Expression={$_.properties.displayName}} | 
            Out-ConsoleGridView -Title "Select rules to deploy" -OutputMode Multiple | 
            Select-Object -ExpandProperty DisplayName

        foreach ($displayName in $selectedRulesDisplayNames) {
            $selectedRule = $exportedRules | Where-Object { $_.properties.displayName -eq $displayName }
            $ruleJson = $selectedRule | ConvertTo-Json -Depth 100
            $newRuleResult = Set-MicrosoftSentinelAutomationRules -SubscriptionId $newSubscriptionId -ResourceGroupName $newResourceGroup -WorkspaceName $newWorkspaceName -JsonString $ruleJson
            Write-Host "Deployed rule: $($selectedRule.properties.displayName)"
            Write-Log "Deployed rule: $($selectedRule.properties.displayName)"
        }
    }
    "all" {
        $newSentinelResources = Get-MicrosoftSentinelResources
        $newSubscriptionId = $newSentinelResources.SubscriptionId
        $newResourceGroup = $newSentinelResources.ResourceGroupName
        $newWorkspaceName = $newSentinelResources.WorkspaceName

        foreach ($rule in $exportedRules) {
            $ruleJson = $rule | ConvertTo-Json -Depth 100
            $newRuleResult = Set-MicrosoftSentinelAutomationRules -SubscriptionId $newSubscriptionId -ResourceGroupName $newResourceGroup -WorkspaceName $newWorkspaceName -JsonString $ruleJson
            Write-Host "Deployed rule: $($rule.name)"
            Write-Log "Deployed rule: $($rule.name)"
        }
    }
    "cancel" {
        Write-Host "Rule deployment operation cancelled by user."
        Write-Log "Rule deployment operation cancelled by user."
    }
}