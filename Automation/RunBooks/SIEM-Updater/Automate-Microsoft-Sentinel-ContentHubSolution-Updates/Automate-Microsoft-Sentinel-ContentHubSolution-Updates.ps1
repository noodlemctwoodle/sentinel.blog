<#
.SYNOPSIS
Update Microsoft Sentinel Content Hub Solutions at Scale.

.DESCRIPTION
How to update Microsoft Sentinel Content Hub Solutions at Scale using PowerShell and REST API.

.NOTES
File Name : Update-ContentHub.ps1
Author    : Microsoft MVP/MCT - Charbel Nemnom
Version   : 2.2
Date      : 29-November-2023
Updated   : 18-March-2024
Requires  : PowerShell 5.1 or PowerShell 7.3.x (Core)
Module    : Az Module

.LINK
To provide feedback or for further assistance please visit:
 https://charbelnemnom.com
#>

param (
    [Parameter(Position = 0, Mandatory = $true, HelpMessage = 'Enter Azure Subscription ID')]
    [string]$subscriptionId,
    [Parameter(Position = 1, Mandatory = $true, HelpMessage = 'Enter Resource Group Name where Microsoft Sentinel is deployed')]
    [string]$resourceGroupName,
    [Parameter(Position = 2, Mandatory = $true, HelpMessage = 'Enter Log Analytics Workspace Name')]
    [string]$workspaceName,
    [Parameter(Position = 3, Mandatory = $true, HelpMessage = 'Enter Log Analytics Workspace Location')]
    [string]$workspaceLocation,
    [Parameter(Mandatory)]
    [ValidateSet("Yes", "No")]
    [String]$preview = 'No'
)

# Ensures you do not inherit an AzContext in your runbook 
Disable-AzContextAutosave -Scope Process 

# Connect to Azure with system-assigned managed identity (automation account) 
Connect-AzAccount -Identity 

# Set Azure Subscription context
Set-AzContext -Subscription $subscriptionId

# Define the latest API Version to use for Sentinel
$apiVersion = "?api-version=2023-11-01"

# Get Content Hub Solutions Function
Function Get-ContentHub {
    param (
        [string]$contentURI            
    )    
    #! Get Az Access Token
    $token = Get-AzAccessToken #This will default to Azure Resource Manager endpoint
    $authHeader = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token.Token
    }
    return Invoke-RestMethod $contentURI -Method 'GET' -Headers $authHeader
}

# Install Content Hub Solutions Function
Function Install-ContentHub {
    param (
        [string]$installURL,
        [string]$installBody            
    )    
    return Invoke-AzRestMethod $installURL -Method 'PUT' -Payload $installBody -Verbose:$false
}

# Define the base Rest API URI Call
$restAPIUri = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/"

# Get [Installed] All Content Hub Solutions
$installedContentHub = (Get-ContentHub -contentURI ($restAPIUri + "contentPackages$($apiVersion)")).value

# Get All Content Hub Solutions
$ContentHub = (Get-ContentHub -contentURI ($restAPIUri + "contentProductPackages$($apiVersion)")).value

if ($preview -eq "Yes") {
    # Filter Installed Content Hub Solutions, which requires update including [Preview] content from getting updated
    $solutions = @()
    foreach ($item in $installedContentHub) {
        $ref = $ContentHub | Where-Object { $_.properties.displayName -eq $item.properties.displayName } 
        if ($ref.properties.version -gt $item.properties.version) {
            $solutions += $ref
        }
    }    
}
else {
    # Filter Installed Content Hub Solutions, which requires update excluding [Preview] content from getting updated
    $solutions = @()
    foreach ($item in $installedContentHub) {
        $ref = $ContentHub | Where-Object { $_.properties.displayName -eq $item.properties.displayName -and $_.properties.isPreview -eq $false } 
        if ($ref.properties.version -gt $item.properties.version) {
            $solutions += $ref
        }
    }    
}
  
if ($solutions.count -eq 0) {
    Write-Output "All the installed Content Hub solutions are currently up to date. No update is required."
}
Else {
    Write-Output "$($solutions.count) Content Hub solutions were found installed and require an update."
    
    foreach ($solution in $solutions) {        
        $singleSolution = Get-ContentHub -contentURI ($restAPIUri + "contentProductPackages/$($solution.name)$($apiVersion)")
        $packagedContent = $singleSolution.properties.packagedContent

        foreach ($resource in $packagedContent.resources) {
            if ($null -ne $resource.properties.mainTemplate.metadata.postDeployment ) {                
                $resource.properties.mainTemplate.metadata.postDeployment = $null 
            } 
        }
        $solutionDisplayName = $solution.properties.displayName -replace " ",""
        $installBody = @{"properties" = @{ 
                "parameters" = @{ 
                    "workspace"          = @{"Value" = $workspaceName }
                    "workspace-location" = @{"Value" = "$workspaceLocation" } 
                } 
                "template"   = $packagedContent
                "mode"       = "Incremental" 
            } 
        } 
        $deploymentName = ("ContenthubBulkInstall-" + $solutionDisplayName)
        if ($deploymentName.Length -gt 62) {
            $deploymentName = $deploymentName.Substring(0, 62)
        }

        $installURL = "https://management.azure.com/subscriptions/$subscriptionid/resourcegroups/$resourceGroupName/providers/Microsoft.Resources/deployments/" + $deploymentName + "?api-version=2021-04-01"
        $installContentHub = Install-ContentHub -installURL $installURL -installBody ($installBody | ConvertTo-Json -EnumsAsStrings -Depth 50 -EscapeHandling EscapeNonAscii)
                        
        try {        
            if (!($installContentHub.StatusCode -in 200, 201)) {
                Write-Host $installContentHub.StatusCode
                Write-Host $installContentHub.Content
                throw "Error when updating Content Hub Solution [$($solution.properties.displayName)]"
            }
            Write-Output "Content Hub Solution [$($solution.properties.displayName)] updated successfully!"
        }
        catch {
            Write-Error $_ -ErrorAction Continue

        }
        Write-Output ("")
    }   
}
