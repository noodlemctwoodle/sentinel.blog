<#

#Requires -Version 7
#Requires -Modules Az.Resources
#Requires -Modules Az.LogicApp
#Requires -Modules Microsoft.PowerShell.ConsoleGuiTools

.SYNOPSIS
This script assigns role permissions to Logic Apps in a Microsoft Sentinel environment.

.DESCRIPTION
The 'Assign-RoleAssignments.ps1' script is designed to automate the process of assigning roles to Logic Apps within Microsoft Sentinel. 
It allows users to select specific Logic Apps and roles, and then applies the selected roles to these apps. The script uses Azure PowerShell modules and requires Azure authentication.

.PARAMETER subscriptionId
The ID of the Azure subscription where the Logic Apps and Microsoft Sentinel resources are located.

.PARAMETER resourceGroupName
The name of the resource group within the Azure subscription that contains the Logic Apps.

.EXAMPLE
PS> .\Assign-RoleAssignments.ps1

.NOTES
Author: noodlemctwoodle
Version: 1.1
Date: 17 January 2024
This script requires Azure PowerShell modules and an authenticated Azure session.
Ensure you have the necessary permissions in Azure to perform role assignments.

#>

$WarningPreference = 'SilentlyContinue'

$tenantId = "<TenantId>"

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO",

        [Parameter(Mandatory = $false)]
        [string]$FunctionName = $MyInvocation.MyCommand.Name
    )
    
    $logFilePath = "$PSScriptRoot\logFile.txt"
    
    # Check if the log file exists, create it if it does not
    if (-not (Test-Path -Path $logFilePath)) {
        try {
            New-Item -Path $logFilePath -ItemType File -Force
        } catch {
            Write-Host "Failed to create log file at path: $logFilePath. Error: $_" -ForegroundColor Red
            return
        }
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - [$Level] - [$FunctionName] - $Message"
    
    try {
        $logEntry | Out-File $logFilePath -Append
    } catch {
        
        Write-Host "Failed to write to log file at path: $logFilePath. Error: $_" -ForegroundColor Red
    }
    
    # Uncomment the following lines if you want to write to the console based on the log level
    # if ($Level -eq "ERROR") {
    #     Write-Host $logEntry -ForegroundColor Red
    # } elseif ($Level -eq "WARNING") {
    #     Write-Host $logEntry -ForegroundColor Yellow
    # } else {
    #     Write-Host $logEntry -ForegroundColor Green
    # }
}

$playbookBicepFilePath = "$PSScriptRoot\Sentinel\addPlaybookRoleAssignment.bicep"
$keyVaultBicepFilePath = "$PSScriptRoot\KeyVault\addKeyVaultRoleAssignment.bicep"

if (Test-Path -Path $playbookBicepFilePath) {
    Write-Log -Message "Playbook Bicep file exists: $playbookBicepFilePath" -Level "INFO" -FunctionName "CheckFilePaths"
} else {
    Write-Log -Message "Playbook Bicep file does not exist: $playbookBicepFilePath" -Level "WARNING" -FunctionName "CheckFilePaths"
}

if (Test-Path -Path $keyVaultBicepFilePath) {
    Write-Log -Message "Key Vault Bicep file exists: $keyVaultBicepFilePath" -Level "INFO" -FunctionName "CheckFilePaths"
} else {
    Write-Log -Message "Key Vault Bicep file does not exist: $keyVaultBicepFilePath" -Level "WARNING" -FunctionName "CheckFilePaths"
}

$jsonFilesDirectory = "$PSScriptRoot\parameters"

if (-not (Test-Path -Path $jsonFilesDirectory)) {
    try {
        New-Item -Path $jsonFilesDirectory -ItemType Directory

        Write-Log -Message "Directory created: $jsonFilesDirectory" -Level "INFO" -FunctionName "CreateJsonFilesDirectory"
    } catch {
        Write-Log -Message "An error occurred while creating the directory: $_" -Level "ERROR" -FunctionName "CreateJsonFilesDirectory"
    }
} else {
    Write-Log -Message "Directory already exists: $jsonFilesDirectory" -Level "INFO" -FunctionName "CreateJsonFilesDirectory"
}

try {
    Write-Log -Message "Attempting to delete all items in the folder." -Level "INFO" -FunctionName "ClearFolderContents"  
    Remove-Item -Path "$PSScriptRoot\parameters\*" -Recurse -Force
    Write-Log -Message "Successfully deleted all items in the folder." -Level "INFO" -FunctionName "ClearFolderContents"
} catch {
    Write-Log -Message "An error occurred while deleting items: $_" -Level "ERROR" -FunctionName "ClearFolderContents"
}

try {
    Write-Log -Message "Attempting to generate a random number." -Level "INFO" -FunctionName "GenerateRandomNumber"
    $randomNumber = Get-Random -Minimum 1000 -Maximum 10000
    Write-Log -Message "Random number generated: $randomNumber" -Level "INFO" -FunctionName "GenerateRandomNumber"
} catch {
    Write-Log -Message "An error occurred while generating a random number: $_" -Level "ERROR" -FunctionName "GenerateRandomNumber"
}

try {
    Write-Log -Message "Attempting to connect to Azure account with specified Tenant ID." -Level "INFO" -FunctionName "ConnectToAzureAccount"
    Connect-AzAccount -TenantId $tenantId
    Write-Log -Message "Successfully connected to Azure account with Tenant ID: $tenantId" -Level "INFO" -FunctionName "ConnectToAzureAccount"
} catch {
    Write-Log -Message "An error occurred while connecting to Azure account: $_" -Level "ERROR" -FunctionName "ConnectToAzureAccount"
}

function Get-LogicAppResources {
    
    Write-Log "Getting Microsoft Sentinel Resources..."

    $subscriptions = Get-AzSubscription | Select-Object -Property Name, Id
    $selectedSubscription = $subscriptions | Out-ConsoleGridView -Title "Select your subscription" -OutputMode Single
    Set-AzContext -SubscriptionId $selectedSubscription.Id
    Write-Log "Selected Subscription ID: $($selectedSubscription.Id)"

    $resourceGroups = Get-AzResourceGroup | Select-Object -Property ResourceGroupName
    $selectedResourceGroup = $resourceGroups | Out-ConsoleGridView -Title "Select your resource group" -OutputMode Single
    Write-Log "Selected Resource Group: $($selectedResourceGroup.ResourceGroupName)"

    $logicApps = Get-AzLogicApp -ResourceGroupName $selectedResourceGroup.ResourceGroupName
    Write-Log "Retrieved $($logicApps.Count) Logic App(s) in Resource Group: $($selectedResourceGroup.ResourceGroupName)"

    if ($logicApps -and $logicApps.Count -gt 0) {
        $logicAppNames = $logicApps | Select-Object -ExpandProperty Name

        try {
            $selectedLogicAppNames = $logicAppNames | Out-ConsoleGridView -Title "Select Logic Apps" -OutputMode Multiple
            if ($selectedLogicAppNames) {
                $matchedSelectedLogicApps = $logicApps | Where-Object { $selectedLogicAppNames -contains $_.Name }
                Write-Log "Selected Logic App(s): $($matchedSelectedLogicApps.Name -join ', ')"
            } else {
                Write-Log "No Logic Apps selected."
                $matchedSelectedLogicApps = @()
            }
        } catch {
            Write-Log "Error while selecting Logic Apps: $_"
        }
    } else {
        Write-Log "No Logic Apps found in the selected Resource Group."
        $matchedSelectedLogicApps = @()
    }

    return @{
        SubscriptionId = $selectedSubscription.Id
        ResourceGroupName = $selectedResourceGroup.ResourceGroupName
        SelectedLogicApps = $matchedSelectedLogicApps
        
    }
}


function Get-KeyVaultResources {
    Write-Log -Message "Starting Key Vault resource retrieval..." -Level "INFO" -FunctionName "Get-KeyVaultResources"

    try {
        $subscriptions = Get-AzSubscription | Select-Object -Property Name, Id
        Write-Log -Message "Retrieved subscriptions." -Level "INFO" -FunctionName "Get-KeyVaultResources"

        $selectedKeyVaultSubscription = $subscriptions | Out-ConsoleGridView -Title "Select your subscription" -OutputMode Single
        if (-not $selectedKeyVaultSubscription) {
            Write-Log -Message "No subscription selected. Exiting." -Level "WARNING" -FunctionName "Get-KeyVaultResources"
            return
        }
        Set-AzContext -SubscriptionId $selectedKeyVaultSubscription.Id
        Write-Log -Message "Selected Subscription ID: $($selectedKeyVaultSubscription.Id)" -Level "INFO" -FunctionName "Get-KeyVaultResources"

        $resourceGroups = Get-AzResourceGroup | Select-Object -Property ResourceGroupName
        Write-Log -Message "Retrieved resource groups." -Level "INFO" -FunctionName "Get-KeyVaultResources"

        $selectedKeyVaultResourceGroup = $resourceGroups | Out-ConsoleGridView -Title "Select your resource group" -OutputMode Single
        if (-not $selectedKeyVaultResourceGroup) {
            Write-Log -Message "No resource group selected. Exiting." -Level "WARNING" -FunctionName "Get-KeyVaultResources"
            return
        }
        Write-Log -Message "Selected Resource Group: $($selectedKeyVaultResourceGroup.ResourceGroupName)" -Level "INFO" -FunctionName "Get-KeyVaultResources"

        $keyVaults = Get-AzKeyVault -ResourceGroupName $selectedKeyVaultResourceGroup.ResourceGroupName
        Write-Log -Message "Retrieved Key Vaults from resource group: $($selectedKeyVaultResourceGroup.ResourceGroupName)" -Level "INFO" -FunctionName "Get-KeyVaultResources"

        if (-not $keyVaults) {
            Write-Log -Message "No Key Vaults found in the selected Resource Group. Exiting." -Level "WARNING" -FunctionName "Get-KeyVaultResources"
            return
        }

        $selectedKeyVault = $keyVaults | Select-Object -Property VaultName | Out-ConsoleGridView -Title "Select your key vault" -OutputMode Single
        if (-not $selectedKeyVault) {
            Write-Log -Message "No Key Vault selected. Exiting." -Level "WARNING" -FunctionName "Get-KeyVaultResources"
            return
        }
        Write-Log -Message "Selected Key Vault: $($selectedKeyVault.VaultName)" -Level "INFO" -FunctionName "Get-KeyVaultResources"

        return @{
            SubscriptionId = $selectedKeyVaultSubscription.Id
            ResourceGroupName = $selectedKeyVaultResourceGroup.ResourceGroupName
            SelectedKeyVault = $selectedKeyVault
        }
    } catch {
        Write-Log -Message "An error occurred during Key Vault resource retrieval: $_" -Level "ERROR" -FunctionName "Get-KeyVaultResources"
    }
}

function Set-PlaybookBicepParameterFiles {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$SelectedLogicApps,

        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true)]
        [hashtable]$RoleDefinitionIds,

        [Parameter(Mandatory=$true)]
        [string]$RoleSelection,

        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory
    )

    Write-Log -Message "Starting to set Playbook Bicep parameter files." -Level "INFO" -FunctionName "Set-PlaybookBicepParameterFiles"

    foreach ($app in $SelectedLogicApps) {
        Write-Log -Message "Processing Logic App: $($app.Name)" -Level "INFO" -FunctionName "Set-PlaybookBicepParameterFiles"
        try {
            $jsonObject = @{
                '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
                'contentVersion' = '1.0.0.0'
                'parameters' = @{
                    'permissions' = @{
                        'value' = @()
                    }
                }
            }

            $logicAppResource = Get-AzResource -ResourceId $app.Id
            $principalId = $logicAppResource.Identity.PrincipalId

            if (-not $principalId) {
                Write-Log -Message "No System Assigned Managed Identity found for Logic App: $($app.Name)" -Level "WARNING" -FunctionName "Set-PlaybookBicepParameterFiles"
                continue
            }

            Write-Log -Message "System Assigned Managed Identity found for Logic App: $($app.Name) with Principal ID: $principalId" -Level "INFO" -FunctionName "Set-PlaybookBicepParameterFiles"

            $permissionObject = @{
                'name'                                = [guid]::NewGuid().ToString()
                'principalId'                         = $principalId
                'roleDefinitionId'                    = $RoleDefinitionIds[$RoleSelection]
                'delegatedManagedIdentityResourceId'  = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Logic/workflows/$($app.Name)"
                'description'                         = "Apply System Assigned Managed Identity Permissions"
                'principalType'                       = "ServicePrincipal"
            }

            $jsonObject.parameters.permissions.value += $permissionObject

            $jsonOutput = $jsonObject | ConvertTo-Json -Depth 10

            $outputFilePath = Join-Path $OutputDirectory ("$(($app.Name).Replace(' ', '_'))_permissions.json")

            $jsonOutput | Out-File -FilePath $outputFilePath -Force

            Write-Log -Message "JSON file for Playbook permissions populated and saved as $outputFilePath" -Level "INFO" -FunctionName "Set-PlaybookBicepParameterFiles"
        } catch {
            Write-Log -Message "An error occurred while setting Playbook Bicep parameter files for Logic App: $($app.Name). Error: $($_.Exception.Message)" -Level "ERROR" -FunctionName "Set-PlaybookBicepParameterFiles"
        }
    }

    Write-Log -Message "Completed setting Playbook Bicep parameter files." -Level "INFO" -FunctionName "Set-PlaybookBicepParameterFiles"
}

function Set-KeyVaultBicepParameterFiles {
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$SelectedLogicApps,

        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true)]
        [string]$keyVaultName,

        [Parameter(Mandatory=$true)]
        [hashtable]$RoleDefinitionIds,

        [Parameter(Mandatory=$true)]
        [string]$RoleSelection,

        [Parameter(Mandatory=$true)]
        [string]$OutputDirectory
    )

    Write-Log -Message "Starting to set Key Vault Bicep parameter files." -Level "INFO" -FunctionName "Set-KeyVaultBicepParameterFiles"

    foreach ($playbook in $SelectedLogicApps) {
        Write-Log -Message "Processing playbook: $($playbook.Name)" -Level "INFO" -FunctionName "Set-KeyVaultBicepParameterFiles"
        try {
            $jsonObject = @{
                '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#'
                'contentVersion' = '1.0.0.0'
                'parameters' = @{
                    'roleName' = @{
                        'value' = 'Key Vault Secrets User'
                    }
                    'keyVaultName' = @{
                        'value' = $keyVaultName
                    }
                    'permissions' = @{
                        'value' = @()
                    }
                }
            }

            $playbookResource = Get-AzResource -ResourceId $playbook.Id
            $principalId = $playbookResource.Identity.PrincipalId

            if (-not $principalId) {
                Write-Log -Message "No System Assigned Managed Identity found for Playbook: $($playbook.Name)" -Level "WARNING" -FunctionName "Set-KeyVaultBicepParameterFiles"
                continue
            }

            Write-Log -Message "System Assigned Managed Identity found for Playbook: $($playbook.Name) with Principal ID: $principalId" -Level "INFO" -FunctionName "Set-KeyVaultBicepParameterFiles"

            $permissionObject = @{
                'name'                                = [guid]::NewGuid().ToString()
                'principalId'                         = $principalId
                'roleDefinitionId'                    = $RoleDefinitionIds[$RoleSelection]
                'delegatedManagedIdentityResourceId'  = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Logic/workflows/$($playbook.Name)"
                'description'                         = "Apply System Assigned Managed Identity Permissions"
                'principalType'                       = "ServicePrincipal"
            }

            $jsonObject.parameters.permissions.value += $permissionObject

            $jsonOutput = $jsonObject | ConvertTo-Json -Depth 10

            $outputFilePath = Join-Path $OutputDirectory ("$(($playbook.Name).Replace(' ', '_'))_keyvault_permissions.json")

            $jsonOutput | Out-File -FilePath $outputFilePath -Force

            Write-Log -Message "JSON file for Key Vault permissions populated and saved as $outputFilePath" -Level "INFO" -FunctionName "Set-KeyVaultBicepParameterFiles"
        } catch {
            Write-Log -Message "An error occurred while setting Key Vault Bicep parameter files for Playbook: $($playbook.Name). Error: $($_.Exception.Message)" -Level "ERROR" -FunctionName "Set-KeyVaultBicepParameterFiles"
        }
    }

    Write-Log -Message "Completed setting Key Vault Bicep parameter files." -Level "INFO" -FunctionName "Set-KeyVaultBicepParameterFiles"
}

try {
    $setPermisssionsSelection = @("Key Vault Permissions", "Playbook Permissions", "Cancel") | Select-Object @{Name = "Response"; Expression = {$_}}
    $setPermissionResponse = $setPermisssionsSelection | Out-ConsoleGridView -Title "Do you want to deploy Key Vault Permissions, Playbook Permissions, or cancel?" -OutputMode Single
    
    Write-Log "User selected: $($setPermissionResponse.Response)" -Level INFO -FunctionName "Permission Selection"
    
} catch {

    Write-Log -Message "An error occurred: $_" -Level ERROR
    
}

switch ($setPermissionResponse.Response) {
    "Key Vault Permissions" {
        try {
            $kvRoleDefinitionIds = @{
                "Key Vault Administrator" = "00482a5a-887f-4fb3-b363-3b7fe8e74483"
                "Key Vault Secrets User" = "4633458b-17de-408a-b874-0445c86b69e6"
            }
        
            Write-Log -Message "Key Vault role definition IDs set." -Level INFO
        
            $azKeyVaultResources = Get-KeyVaultResources
            Write-Log -Message "Azure Key Vault resources retrieved." -Level INFO
        
            $msSentinelResources = Get-LogicAppResources
            Write-Log -Message "Microsoft Sentinel Logic App resources retrieved." -Level INFO
        
            $roleSelection = $kvRoleDefinitionIds.Keys | Out-ConsoleGridView -Title "Select Role" -OutputMode Single
            
            if (-not $roleSelection) {
                Write-Log -Message "No role selected. Exiting script." -Level WARNING
                exit
            }
            
            Write-Log -Message "Role selected: $roleSelection" -Level INFO
        
            Set-KeyVaultBicepParameterFiles `
                -SelectedLogicApps $msSentinelResources.SelectedLogicApps `
                -SubscriptionId $msSentinelResources.SubscriptionId `
                -ResourceGroupName $msSentinelResources.ResourceGroupName `
                -KeyVaultName $azKeyVaultResources.SelectedKeyVault.VaultName `
                -RoleDefinitionIds $kvRoleDefinitionIds `
                -RoleSelection $roleSelection `
                -OutputDirectory $jsonFilesDirectory
            
            Write-Log -Message "Key Vault Bicep parameter files set for role: $roleSelection" -Level INFO
        
            $jsonFiles = Get-ChildItem -Path $jsonFilesDirectory -Filter "*.json"
            Write-Log -Message "JSON files for deployment retrieved." -Level INFO
            
            foreach ($jsonFile in $jsonFiles) {
                $jsonFilePath = $jsonFile.FullName
                Write-Log -Message "Starting deployment with template: $jsonFilePath" -Level INFO
        
                try {
                    New-AzResourceGroupDeployment `
                        -name "roleAssignment.template-$(Get-Date -Format 'yyyyMMdd')-$randomNumber" `
                        -ResourceGroupName $msSentinelResources.ResourceGroupName `
                        -TemplateFile $keyVaultBicepFilePath `
                        -TemplateParameterFile $jsonFilePath
                    Write-Log -Message "Deployment succeeded for template: $jsonFilePath" -Level INFO
                } catch {
                    Write-Log -Message "Deployment failed for template: $jsonFilePath. Error: $($_.Exception.Message)" -Level ERROR
                }
            }
        } catch {
            Write-Log -Message "An error occurred while deploying Key Vault Permissions: $_" -Level ERROR
        }        
    }
    "Playbook Permissions" {
        try {
            $pbRoleDefinitionIds = @{
                "Microsoft Sentinel Contributor" = "ab8e14d6-4a74-4a29-9ba8-549422addade"
                "Microsoft Sentinel Responder" = "3e150937-b8fe-4cfb-8069-0eaf05ecd056"
            }
            
            Write-Log -Message "Playbook role definition IDs set." -Level INFO
    
            $msSentinelResources = Get-LogicAppResources
            
            Write-Log -Message "Retrieved Microsoft Sentinel resources." -Level INFO
            
            $roleSelection = $pbRoleDefinitionIds.Keys | Out-ConsoleGridView -Title "Select Role" -OutputMode Single
            
            if (-not $roleSelection) {
                Write-Log -Message "No role selected. Exiting script." -Level WARNING
                exit
            }
            
            Write-Log -Message "Role selected: $roleSelection" -Level INFO
            
            Set-PlaybookBicepParameterFiles `
                -SelectedLogicApps $msSentinelResources.SelectedLogicApps `
                -SubscriptionId $msSentinelResources.SubscriptionId `
                -ResourceGroupName $msSentinelResources.ResourceGroupName `
                -RoleDefinitionIds $pbRoleDefinitionIds `
                -RoleSelection $roleSelection `
                -OutputDirectory $jsonFilesDirectory
            
            Write-Log -Message "Set playbook Bicep parameter files for role: $roleSelection" -Level INFO
            
            $jsonFiles = Get-ChildItem -Path $jsonFilesDirectory -Filter "*.json"
            
            Write-Log -Message "Retrieved JSON files for deployment." -Level INFO
            
            foreach ($jsonFile in $jsonFiles) {
                $jsonFilePath = $jsonFile.FullName
                Write-Log -Message "Starting deployment with template: $jsonFilePath" -Level INFO
        
                try {
                    New-AzResourceGroupDeployment `
                        -name "roleAssignment.template-$(Get-Date -Format 'yyyyMMdd')-$randomNumber" `
                        -ResourceGroupName $msSentinelResources.ResourceGroupName `
                        -TemplateFile $playbookBicepFilePath `
                        -TemplateParameterFile $jsonFilePath
                    Write-Log -Message "Deployment succeeded for template: $jsonFilePath" -Level INFO
                } catch {
                    Write-Log -Message "Deployment failed for template: $jsonFilePath. Error: $($_.Exception.Message)" -Level ERROR
                }
            }
        } catch {
            Write-Log -Message "An error occurred while processing JSON files: $_" -Level ERROR
        }
    }
    "cancel" {
        Write-Log -Message "Rule deployment operation cancelled by user." -Level WARNING
    }
}