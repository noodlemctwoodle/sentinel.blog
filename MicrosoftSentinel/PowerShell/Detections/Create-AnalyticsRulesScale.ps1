<#
.SYNOPSIS
Enable Microsoft Sentinel Analytics Rules at Scale.

.DESCRIPTION
How to create and enable Microsoft Sentinel Analytics Rules at Scale using PowerShell.

.NOTES
File Name : Set-AnalyticsRules.ps1
Author : Microsoft MVP/MCT - Charbel Nemnom
Version : 1.0
Date : 24-October-2022
Update : 25-October-2022
Requires : PowerShell 5.1 or PowerShell 7.2.x (Core)
Module : Az Module & Az Resource Graph

.LINK
To provide feedback or for further assistance please visit: https://charbelnemnom.com

.EXAMPLE
.\Set-AnalyticsRules.ps1 -SubscriptionId "SUB-ID" -ResourceGroup "RG-Name" `
-WorkspaceName "Log-Analytics-Name" -SolutionName "Source-Name" -enableRules [Yes] -Verbose
This example will connect to your Azure account using the subscription Id specified, and then create all analytics rules from templates for the specified Microsoft Sentinel solution.
By default, all of the rules will be created in a Disabled state. You have the option to enable the rules at creation time by setting the parameter -enableRules [Yes].
#>

param (
    [Parameter(Position = 0, Mandatory = $true, HelpMessage = 'Enter Azure Subscription ID')]
    [string]$subscriptionId,
    [Parameter(Position = 1, Mandatory = $true, HelpMessage = 'Enter Resource Group Name where Microsoft Sentinel is deployed')]
    [string]$resourceGroupName,
    [Parameter(Position = 2, Mandatory = $true, HelpMessage = 'Enter Log Analytics Workspace Name')]
    [string]$workspaceName,
    [Parameter(Position = 3, Mandatory = $true, HelpMessage = 'Enter Microsoft Sentinel Solution Name')]
    [string]$solutionName,
    [ValidateSet("Yes", "No")]
    [String]$enableRules = 'No'
)

#! Install Az Module If Needed
function Install-Module-If-Needed {
    param([string]$ModuleName)

    if (Get-Module -ListAvailable -Name $ModuleName) {
        Write-Host "Module '$($ModuleName)' already exists, continue..." -ForegroundColor Green
    }
    else {
        Write-Host "Module '$($ModuleName)' does not exist, installing..." -ForegroundColor Yellow
        Install-Module $ModuleName -Force -AllowClobber -ErrorAction Stop
        Write-Host "Module '$($ModuleName)' installed." -ForegroundColor Green
    }
}

#! Install Az Resource Graph Module If Needed
Install-Module-If-Needed Az.ResourceGraph

#! Install Az Accounts Module If Needed
Install-Module-If-Needed Az.Accounts

#! Check Azure Connection
#Try {
#    Write-Verbose "Connecting to Azure Cloud..."
#    Connect-AzAccount -ErrorAction Stop | Out-Null
#}
#Catch {
#    Write-Warning "Cannot connect to Azure Cloud. Please check your credentials. Exiting!"
#    Break
#}

$rgQuery = @"
resources
| where type =~ 'Microsoft.Resources/templateSpecs/versions'
| where tags['hidden-sentinelContentType'] =~ 'AnalyticsRule' and tags['hidden-sentinelWorkspaceId'] =~ '/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName'
| extend workspaceName = strcat(split('/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName', "/")[-1],'-')
| extend versionArray=split(id, "/")
| extend content_kind = tags['hidden-sentinelContentType']
| extend version = name
| extend parsed_version = parse_version(version)
| extend resources = parse_json(parse_json(parse_json(properties).template).resources)
| extend metadata = parse_json(resources[array_length(resources)-1].properties)
| extend contentId=tostring(metadata.contentId)
| summarize arg_max(parsed_version, version, properties) by contentId
| project contentId, version, properties
| mv-expand solution = properties.template.resources
| where solution.properties.source.name == '$($solutionName)'
| project-away solution
"@

Write-Output $rgQuery

try {
    $templates = Search-AzGraph -Query $rgQuery
    if ($templates.Count -eq 0) {
        throw "Resource Graph query error"
    }
}
catch {
    Write-Error $_ -ErrorAction Stop
}

foreach ($template in $templates) {
    $ruleId = $template.contentId
    $rule = $template.properties.template.resources | Where-Object type -eq 'Microsoft.SecurityInsights/AlertRuleTemplates' | Select-Object kind, properties
    $rule.properties | Add-Member -NotePropertyName alertRuleTemplateName -NotePropertyValue $ruleId
    $rule.properties | Add-Member -NotePropertyName templateVersion -NotePropertyValue $template.version

    If ($enableRules -eq "Yes") {
        $rule.properties.enabled = $true
    }

    $payload = $rule | ConvertTo-Json -Depth 100
    $apiPath = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules/$($ruleId)?api-version=2022-09-01-preview"
    try {
        $result = Invoke-AzRestMethod -Method PUT -path $apiPath -Payload $payload
        If ($enableRules -eq "Yes") {
            Write-Verbose "Creating and Enabling rule $($rule.properties.displayName)"
        }
        Else {
            Write-Verbose "Creating rule $($rule.properties.displayName)"
        }
        if (!($result.StatusCode -in 200, 201)) {
            Write-Host $result.StatusCode
            Write-Host $result.Content
            throw "Error when enabling Analytics rule $($rule.properties.displayName)"
        }
    }
    catch {
        Write-Error $_ -ErrorAction Continue
    }
}