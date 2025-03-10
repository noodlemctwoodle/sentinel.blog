<#
.SYNOPSIS
Update Microsoft Sentinel "My Workbooks" Templates at Scale.

.DESCRIPTION
How to automatically update Microsoft Sentinel "My Workbooks" Templates at Scale using PowerShell and REST API.

.NOTES
File Name : Update-SentinelWorkbooks.ps1
Author    : Microsoft MVP/MCT - Charbel Nemnom
Version   : 1.0
Date      : 04-October-2024
Updated   : 07-October-2024
Requires  : PowerShell 7.4.x (Core)
Module    : Az Module
Service   : Automation Accounts

.LINK
To provide feedback or for further assistance please visit:
 https://charbelnemnom.com 

.EXAMPLE
.\Update-SentinelWorkbooks.ps1 -SubscriptionId <SUB-ID> -ResourceGroup <RG-Name> -WorkspaceName <Log-Analytics-Name> -Verbose
This example will connect to your Azure account using the subscription ID specified. Then, check all the installed and saved Workbooks in Microsoft Sentinel.
Then, it will check if the saved Workbook(s) are outdated compared to the installed template(s) from Content Hub.
If the saved Workbook(s) is outdated, it will update the saved Workbook(s) to the latest template version available.
#>

param (
    [Parameter(Position = 0, Mandatory = $true, HelpMessage = 'Enter Azure Subscription ID')]
    [string]$subscriptionId,
    [Parameter(Position = 1, Mandatory = $true, HelpMessage = 'Enter Resource Group Name where Microsoft Sentinel is deployed')]
    [string]$resourceGroupName,
    [Parameter(Position = 2, Mandatory = $true, HelpMessage = 'Enter Log Analytics Workspace Name')]
    [string]$workspaceName  
)

# Ensures you do not inherit an AzContext in your runbook 
Disable-AzContextAutosave -Scope Process 

#! Check Azure Connection
Try {
    Write-Output "Connecting to Azure Cloud..."
    # Connect to Azure with system-assigned managed identity (automation account)
    Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
}
Catch {
    Write-Warning "Cannot connect to Azure Cloud. Please check your managed identity Azure RBAC access. Exiting!"
    Break
}

# Set Azure Subscription context
Set-AzContext -Subscription $subscriptionId

# Define the API Version to use for Microsoft Sentinel and Application Insights
$sentinelApiVersion = "api-version=2024-04-01-preview"
$appInsightsApiVersion = "api-version=2023-06-01"

#! Get Az Access Token
# This will default to Azure Resource Manager endpoint
# Note: Add the [-AsSecureString] parameter, the change is expected to take effect in Az module version: '13.0.0' and later
Write-Verbose "Getting Azure Access Token..." -Verbose
$token = Get-AzAccessToken -TenantId $azAccount.Tenant.id
$authHeader = @{
    'Content-Type'  = 'application/json'
    'Authorization' = 'Bearer ' + $token.Token
}

# Get all installed Microsoft Sentinel Workbook Templates
Write-Verbose "Getting all installed Microsoft Sentinel Workbook Templates..." -Verbose
$workbookTemplateURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contenttemplates?$($sentinelApiVersion)&%24filter=(properties%2FcontentKind%20eq%20'Workbook')"
$workbookContentTemplates = (Invoke-RestMethod $workbookTemplateURI -Method 'GET' -Headers $authHeader).value
try {     
    if ($workbookContentTemplates.Count -eq 0) { 
        throw "No Workbook templates can be found in Microsoft Sentinel. Please install Workbooks from the Content Hub blade!" 
    } 
} 
catch { Write-Error $_ -ErrorAction Stop }
Write-Verbose "$($workbookContentTemplates.count) Microsoft Sentinel installed Workbook templates were found..." -Verbose

# Get all saved Microsoft Sentinel Workbooks
Write-Verbose "Getting all saved Microsoft Sentinel Workbooks..." -Verbose
$installedWorkbookURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.Insights/workbooks?$($appInsightsApiVersion)&canFetchContent=false&%24filter=sourceId%20eq%20'%2Fsubscriptions%2F$($subscriptionid)%2Fresourcegroups%2F$($resourceGroupName)%2Fproviders%2Fmicrosoft.operationalinsights%2Fworkspaces%2F$($workspaceName)'&category=sentinel"
$installedWorkbookResponse = (Invoke-RestMethod $installedWorkbookURI -Method 'GET' -Headers $authHeader).value
try { 
    if ($installedWorkbookResponse.Count -eq 0) { 
        throw "No saved Workbook can be found in the resource group: $($resourceGroupName). Please save Microsoft Sentinel Workbooks from the Templates tab!" 
    } 
} 
catch { Write-Error $_ -ErrorAction Stop }
Write-Verbose "$($installedWorkbookResponse.Count) Microsoft Sentinel saved Workbooks were found..." -Verbose

# Filter out the saved workbooks from the installed Workbook templates
Write-Verbose "Filter out Microsoft Sentinel saved Workbooks from the installed Workbook templates from Content Hub..." -Verbose
$installedWorkbookMetadataURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/metadata?$($sentinelApiVersion)&%24filter=(properties%2FKind%20eq%20'Workbook')"
$installedWorkbookMetadataResponse = (Invoke-RestMethod $installedWorkbookMetadataURI -Method 'GET' -Headers $authHeader).value
$installedWorkbookTemplates = $workbookContentTemplates | Where-Object { $installedWorkbookMetadataResponse.properties.contentId -eq $_.properties.contentId }
try {
    if ($installedWorkbookTemplates.count -eq 0) {
        throw  "No saved Workbooks were found that match the installed Microsoft Sentinel Workbook templates from Content Hub..."
    }    
} 
catch { Write-Error $_ -ErrorAction Stop }
Write-Verbose "$($installedWorkbookTemplates.count) Microsoft Sentinel saved Workbooks remained..." -Verbose

$workbookUpdates = @()

# Checking if the remaining saved Workbooks are outdated and need to be updated
Write-Verbose "Checking if the remaining saved Workbooks version are outdated and need to be updated..." -Verbose
foreach ($installedWorkbookTemplate in $installedWorkbookTemplates) {

    $oldMetadataName = ($installedWorkbookMetadataResponse | Where-Object { $installedWorkbookTemplate.properties.contentId -eq $_.properties.contentId }).name
    $oldWorkbookName = $oldMetadataName -replace 'workbook-', ''

    $workbookURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/metadata/$($oldMetadataName)?$($sentinelApiVersion)"
    $workbookResponse = Invoke-RestMethod $workbookURI -Method 'GET' -Headers $authHeader -Verbose:$false  

    if ($workbookResponse.properties.version -ne $installedWorkbookTemplate.properties.version) {
        Write-Verbose "Microsoft Sentinel Workbook [$($installedWorkbookTemplate.properties.displayName)] is outdated `
         and running version [$($workbookResponse.properties.version)] and needs to be updated to version [$($installedWorkbookTemplate.properties.version)]" -Verbose        
        Write-Verbose "Updating Microsoft Sentinel Workbook [$($installedWorkbookTemplate.properties.displayName)]..." -Verbose        

        # Deleting outdated workbook
        Write-Verbose "Deleting the outdated Microsoft Sentinel Workbook [$($installedWorkbookTemplate.properties.displayName)] version [$($workbookResponse.properties.version)]..." -Verbose
        $deleteOldWorkbookURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.Insights/workbooks/$($oldWorkbookName)?$($appInsightsApiVersion)"
        $deleteOldWorkbookResponse = Invoke-RestMethod $deleteOldWorkbookURI -Method 'DELETE' -Headers $authHeader -Verbose:$false

        # Deleting the metadata of the outdated workbook
        Write-Verbose "Deleting the metadata of the outdated Microsoft Sentinel Workbook [$($installedWorkbookTemplate.properties.displayName)] version [$($workbookResponse.properties.version)]..." -Verbose
        $deleteMetadataWorkbookURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/metadata/$($oldMetadataName)?$($sentinelApiVersion)"
        $deleteMetadataWorkbookResponse = Invoke-RestMethod $deleteMetadataWorkbookURI -Method 'DELETE' -Headers $authHeader -Verbose:$false 

        # Generate a new GUID for the new workbook
        Write-Verbose "Generating a new GUID for the new Microsoft Sentinel Workbook [$($installedWorkbookTemplate.properties.displayName)]" -Verbose
        $guid = (New-Guid).Guid        
        $newWorkbookName = ($workbookContentTemplates | Where-Object { $installedWorkbookTemplate.properties.contentId -eq $_.properties.contentId }).Name      
        $newWorkbookURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contenttemplates/$($newWorkbookName)?$($sentinelApiVersion)"
        $newWorkbookResponse = (Invoke-RestMethod $newWorkbookURI -Method 'GET' -Headers $authHeader).properties.mainTemplate.resources
        $newWorkbook = $newWorkbookResponse | Where-Object type -eq 'Microsoft.Insights/workbooks'
        $newWorkbook = $newWorkbook | Select-Object * -ExcludeProperty apiVersion, metadata, name
        $newWorkbook | Add-Member -NotePropertyName name -NotePropertyValue $guid 
        $newWorkbookPayload = $newWorkbook | ConvertTo-Json -EnumsAsStrings -Depth 50
        # Updating to the latest Microsoft Sentinel workbook version
        Write-Verbose "Updating to the latest Microsoft Sentinel Workbook [$($installedWorkbookTemplate.properties.displayName)] to version [$($installedWorkbookTemplate.properties.version)]..." -Verbose
        $createNewWorkbookURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.Insights/workbooks/$($guid)?$($appInsightsApiVersion)"        
        try {        
            $createNewWorkbookResponse = Invoke-AzRestMethod $createNewWorkbookURI -Payload $newWorkbookPayload -Method 'PUT' -Verbose:$false    
            If (!($createNewWorkbookResponse.StatusCode -in 200, 201)) {
                Write-Warning $workbookResult.StatusCode
                Write-Warning $workbookResult.Content
                throw "Error when updating the latest Microsoft Sentinel Workbook [$($installedWorkbookTemplate.properties.displayName)] to version [$($installedWorkbookTemplate.properties.version)]"
            }        
            else {
                Write-Verbose "Microsoft Sentinel Workbook [$($installedWorkbookTemplate.properties.displayName)] is updated to version [$($installedWorkbookTemplate.properties.version)]!" -Verbose                
            }
        }
        catch {
            Write-Error $_ -ErrorAction Continue
        }

        # Updating the metadata of the new workbook
        Write-Verbose "Updating the metadata of the new Microsoft Sentinel Workbook [$($installedWorkbookTemplate.properties.displayName)] to version [$($installedWorkbookTemplate.properties.version)]..." -Verbose
        $newWorkbookMetadata = $newWorkbookResponse | Where-Object type -eq 'Microsoft.OperationalInsights/workspaces/providers/metadata'
        $newWorkbookMetadata = $newWorkbookMetadata | Select-Object * -ExcludeProperty apiVersion, name
        $newWorkbookMetadata | Add-Member -NotePropertyName name -NotePropertyValue "workbook-$($guid)"              
        $workbookParentId = $newWorkbookMetadata.properties.parentId -replace '/[^/]+$', "/$guid"        
        $newWorkbookMetadata.properties | Add-Member -NotePropertyName parentId -NotePropertyValue $workbookParentId -Force        
        $newWorkbookMetadataPayload = $newWorkbookMetadata | ConvertTo-Json -EnumsAsStrings -Depth 50        
        $updateMetadataWorkbookURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/metadata/workbook-$($guid)?$($sentinelApiVersion)"
        try {        
            $updateMetadataWorkbookResponse = Invoke-AzRestMethod $updateMetadataWorkbookURI -Payload $newWorkbookMetadataPayload -Method 'PUT' -Verbose:$false   
            If (!($updateMetadataWorkbookResponse.StatusCode -in 200, 201)) {
                Write-Warning $workbookResult.StatusCode
                Write-Warning $workbookResult.Content
                throw "Error when updating the metadata of the Microsoft Sentinel Workbook [$($installedWorkbookTemplate.properties.displayName)] to version [$($installedWorkbookTemplate.properties.version)]"
            }        
            else {
                Write-Verbose "Microsoft Sentinel Workbook metada [$($installedWorkbookTemplate.properties.displayName)] is updated to version [$($installedWorkbookTemplate.properties.version)]!" -Verbose                
                $workbookUpdates += $installedWorkbookTemplate
            }
        }
        catch {
            Write-Error $_ -ErrorAction Continue
        }           
    }
    else {
        Write-Verbose "Microsoft Sentinel Workbook: [$($installedWorkbookTemplate.properties.displayName)] is already up-to-date!" -Verbose               
    }    
}
Write-Verbose "$($workbookUpdates.count) Microsoft Sentinel saved workbooks were updated!" -Verbose