#requires -version 6.2
<#
    .SYNOPSIS
        Export one or more automation rules to JSON file(s)
    .DESCRIPTION
        The Export-AzSentinelAutomationRule cmdlet exports one or more Automation rules from the specified workspace.  If you specify the 
        AutomationRuleId parameter, a single Automation rule is exported.  If you do not specify the AutomationRuleId parameter, all the 
        automation rules in the specified workspace will be exported.  The filename format is <displayName>.json
    .PARAMETER WorkSpaceName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER ResourceGroupName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER AutomationRuleId
        Enter the Microsoft Sentinel Automation rule Id, this is an optional parameter
    .NOTES
        AUTHOR: Gary Bushey
        LASTEDIT: 8 May 2022
    .EXAMPLE
        Export-AzSentinelAutomationRuletoJSON -WorkspaceName "workspacename" -ResourceGroupName "rgname" -AutomationRuleName "rulename"
        In this example a single JSON file will be created containing the JSON for the automation rule

#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkSpaceName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [string]$AutomationRuleId
)
Function Export-AzSentinelAutomationRuleToJSON ($workspaceName, $resourceGroupName, $rulename) {


    #Setup the Authentication header needed for the REST calls
    $context = Get-AzContext
    $profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profile)
    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json' 
        'Authorization' = 'Bearer ' + $token.AccessToken 
    }
    
    $SubscriptionId = (Get-AzContext).Subscription.Id

    if ($rulename) {
        #Load the templates so that we can copy the information as needed
        $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/automationRules/$($rulename)?api-version=2021-10-01-preview"
        $results = (Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader )

        $resultJson = ConvertTo-Json $results -depth 100
        $resultDisplayName = $results.properties.displayName
        $resultJson | Out-File ($resultDisplayName + ".json")
    }
    else {
        $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/automationRules/?api-version=2021-10-01-preview"
        $results = (Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader ).value

        foreach ($result in $results) {
            $resultJson = ConvertTo-Json $result -depth 100
            $resultDisplayName = $result.properties.displayName
            $resultJson | Out-File ($resultDisplayName + ".json")
        }
    }
}



Export-AzSentinelAutomationRuleToJSON $WorkSpaceName $ResourceGroupName $AutomationRuleId 