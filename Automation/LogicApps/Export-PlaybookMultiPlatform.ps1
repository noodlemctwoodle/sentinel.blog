#requires -Version 7.0
#requires -Module Az.Accounts

<#
.SYNOPSIS
    Logic App ARM Template Export Script

.DESCRIPTION
    This script helps you select and export Logic Apps (including Sentinel Playbooks)
    as ARM templates. It guides you through selecting a tenant, subscription, resource group,
    and one or more Logic Apps. It can optionally generate templates suitable for gallery deployment
    and can update the required Az modules.

    It also allows you to change the default export location for the generated templates,
    and ensures you have both the Az.Accounts module and Microsoft.PowerShell.ConsoleGuiTools module
    installed, prompting you to install them if not found.

    This script is designed to run on PowerShell 7 or later, and is compatible with 
    Windows, macOS, and Linux environments.

.AUTHOR
    noodlemctwoodle

    Thanks to Sreedhar Ande for Playbook-ARM-Template-Generator script, which was used as a reference.

.VERSION
    1.0.0

.NOTES
    Requirements:
      - PowerShell 7.0 or higher
      - Will prompt to install Az.Accounts module if missing.
      - Will prompt to install Microsoft.PowerShell.ConsoleGuiTools module if missing.
    This script leverages Out-ConsoleGridView, which is provided by ConsoleGuiTools.

    Run this script in a PowerShell 7+ terminal that supports ANSI colors for best experience.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId
)

Write-Host "************************************************************" -ForegroundColor Green
Write-Host "*          Logic App ARM Template Export Script            *" -ForegroundColor Green
Write-Host "************************************************************" -ForegroundColor Green
Write-Host "This script will help you select and export Logic Apps as ARM templates." -ForegroundColor Green
Write-Host "By default, the output will be saved to:" -ForegroundColor Green
Write-Host        "$PSScriptRoot" -ForegroundColor Red
Write-Host "You can choose to change this location if desired." -ForegroundColor Green
Write-Host "Running on PowerShell 7+, multi-platform compatible." -ForegroundColor Green
Write-Host "************************************************************" -ForegroundColor Green
Write-Host ""

Function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("Information", "Warning", "Error", "Debug")][string]$Severity = 'Information'
    )

    # Get the script root directory
    $ScriptRoot = $PSScriptRoot
    if (-not $ScriptRoot) {
        $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
        if (-not $ScriptRoot) {
            $ScriptRoot = (Get-Location).Path
        }
    }

    # Define the log file path
    $LogFile = Join-Path -Path $ScriptRoot -ChildPath "ScriptLog.txt"

    # Build the log entry with timestamp and severity
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$TimeStamp] [$Severity] $Message"

    # Write to the console with appropriate color
    switch ($Severity) {
        #"Information" { Write-Host $LogEntry -ForegroundColor Green }
        "Warning"     { Write-Host $LogEntry -ForegroundColor Yellow }
        "Error"       { Write-Host $LogEntry -ForegroundColor Red }
        "Debug"       { Write-Host $LogEntry -ForegroundColor Cyan }
    }

    # Append to the log file
    try {
        Add-Content -Path $LogFile -Value $LogEntry
    } catch {
        Write-Host "Failed to write log to file: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Function Initialize-ExportFolder {
    param (
        [string]$DefaultExportFolder
    )

    # Log the start of the folder initialization process
    Write-Log -Message "Initializing export folder. Default location: $DefaultExportFolder" -Severity "Information"

    # Prompt user if they want to change the export location from the default.
    $ChangeLocationQuestion = "Would you like to change the default export location?"
    $ChangeLocationChoices = New-Object System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]
    $ChangeLocationChoices.Add((New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Change the export folder location'))
    $ChangeLocationChoices.Add((New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Use the default export folder location'))

    $ChangeLocationDecision = $Host.UI.PromptForChoice(
        "Change Export Location",
        $ChangeLocationQuestion,
        $ChangeLocationChoices,
        1
    )

    if ($ChangeLocationDecision -eq 0) {
        # User chose to change the export location.
        $startingPath = $HOME
        Write-Log -Message "User chose to change the export location. Starting path: $startingPath" -Severity "Information"

        # Get list of directories to present for selection
        try {
            $directories = Get-ChildItem -Directory -Path $startingPath | Select-Object Name,FullName
            Write-Log -Message "Directories retrieved for selection." -Severity "Debug"
        } catch {
            Write-Log -Message "Failed to retrieve directories: $($_.Exception.Message)" -Severity "Error"
            exit 1
        }

        # Present directories in a grid view for selection.
        $selectedDirectory = $directories | Out-ConsoleGridView -Title "Select Export Folder (Press ENTER when done)" -OutputMode Single

        if (-not $selectedDirectory) {
            # If no directory was selected, notify and fallback to default location.
            Write-Log -Message "No directory selected. Falling back to default location: $DefaultExportFolder" -Severity "Warning"
            $ExportFolder = $DefaultExportFolder
        } else {
            # User selected a directory; use it as the export folder.
            Write-Log -Message "User selected export folder: $($selectedDirectory.FullName)" -Severity "Information"
            $ExportFolder = $selectedDirectory.FullName
        }
    } else {
        # User chose to use the default location.
        Write-Log -Message "User chose to use the default export location: $DefaultExportFolder" -Severity "Information"
        $ExportFolder = $DefaultExportFolder
    }

    # Ensure the selected or default export folder exists.
    if (-not (Test-Path -Path $ExportFolder)) {
        Write-Log -Message "Export folder does not exist. Creating: $ExportFolder" -Severity "Warning"
        try {
            New-Item -Path $ExportFolder -ItemType Directory -Force | Out-Null
            Write-Log -Message "Export folder created successfully: $ExportFolder" -Severity "Information"
        } catch {
            Write-Log -Message "Failed to create export folder: $ExportFolder. Error: $($_.Exception.Message)" -Severity "Error"
            exit 1
        }
    } else {
        Write-Log -Message "Export folder already exists: $ExportFolder" -Severity "Information"
    }

    # Return the selected or default export folder.
    Write-Log -Message "Export folder initialization complete. Folder path: $ExportFolder" -Severity "Information"
    return $ExportFolder
}

# Initialize default folder
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$DefaultExportFolder = Join-Path $ScriptRoot "Exports"
Write-Log -Message "Default export folder path: $DefaultExportFolder" -Severity "Debug"

$ExportFolder = Initialize-ExportFolder -DefaultExportFolder $DefaultExportFolder

Write-Log -Message "Export folder is set to: $ExportFolder" -Severity "Information"

Function Ensure-Module {
    param (
        [string]$ModuleName,
        [string]$InstallMessage,
        [string]$InstallCommand
    )
    Write-Log -Message "Checking if module '$ModuleName' is installed..." -Severity "Information"

    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Log -Message "Module '$ModuleName' is not installed. Prompting user for installation." -Severity "Warning"

        $InstallQuestion = "The $ModuleName module is required. Do you want to install it now?"
        $InstallChoices = New-Object System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]
        $InstallChoices.Add((New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', "Install the $ModuleName module"))
        $InstallChoices.Add((New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', "Do not install and exit"))

        $InstallDecision = $Host.UI.PromptForChoice(
            "Install $ModuleName",
            $InstallQuestion,
            $InstallChoices,
            1
        )

        if ($InstallDecision -eq 0) {
            Write-Log -Message "$InstallMessage" -Severity "Information"
            try {
                Invoke-Expression $InstallCommand
                Import-Module $ModuleName -ErrorAction Stop
                Write-Log -Message "Module '$ModuleName' installed and imported successfully." -Severity "Information"
            } catch {
                Write-Log -Message "Failed to install module '$ModuleName': $($_.Exception.Message)" -Severity "Error"
                Write-Log -Message "Exiting script due to missing required module." -Severity "Error"
                exit 1
            }
        } else {
            Write-Log -Message "User chose not to install module '$ModuleName'. Exiting..." -Severity "Error"
            exit 1
        }
    } else {
        Write-Log -Message "Module '$ModuleName' is already installed. Importing..." -Severity "Information"
        Import-Module $ModuleName -ErrorAction SilentlyContinue
    }
}

Function Prompt-ForChoice {
    param (
        [string]$Title,
        [string]$Question,
        [System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]]$Choices,
        [int]$DefaultChoice = 1
    )

    Write-Log -Message "Prompting user: $Question" -Severity "Information"
    $Decision = $Host.UI.PromptForChoice($Title, $Question, $Choices, $DefaultChoice)
    return $Decision
}

Function Update-AzModulesIfNeeded {
    param(
        [bool]$ShouldUpdate
    )

    if ($ShouldUpdate) {
        Write-Log -Message "Updating Az Modules to the latest version..." -Severity "Information"
        try {
            Install-Module Az -Scope CurrentUser -Force -ErrorAction Stop
            Import-Module Az -Force -ErrorAction Stop
            Write-Log -Message "Az Modules successfully updated." -Severity "Information"
        } catch {
            Write-Log -Message "Failed to update Az Modules: $($_.Exception.Message)" -Severity "Error"
        }
    } else {
        Write-Log -Message "Skipping Az Module update as per user choice." -Severity "Information"
    }
}

# Main script logic starts here
Write-Log -Message "Starting script. Checking required modules..." -Severity "Information"

# Ensure Az.Accounts module is installed
Ensure-Module -ModuleName "Az.Accounts" `
              -InstallMessage "Installing Az.Accounts module. This may take a few moments..." `
              -InstallCommand "Install-Module Az.Accounts -Scope CurrentUser -Force"

# Ensure Microsoft.PowerShell.ConsoleGuiTools module is installed
Ensure-Module -ModuleName "Microsoft.PowerShell.ConsoleGuiTools" `
              -InstallMessage "Installing Microsoft.PowerShell.ConsoleGuiTools module. This may take a few moments..." `
              -InstallCommand "Install-Module Microsoft.PowerShell.ConsoleGuiTools -Scope CurrentUser -Force"

# Prompt user for gallery template generation
$TemplateGalleryChoices = New-Object System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]
$TemplateGalleryChoices.Add((New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Generate the ARM template with gallery-specific configurations'))
$TemplateGalleryChoices.Add((New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Generate a standard ARM template without gallery-specific configurations'))

$TemplateGalleryDecision = Prompt-ForChoice -Title "Gallery Template Generation" `
                                             -Question "Generate ARM Template for Gallery?" `
                                             -Choices $TemplateGalleryChoices `
                                             -DefaultChoice 1
$GenerateForGallery = $TemplateGalleryDecision -eq 0
Write-Log -Message "User decision for gallery template generation: $GenerateForGallery" -Severity "Information"

# Prompt user for Az module updates
$UpdateModulesChoices = New-Object System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]
$UpdateModulesChoices.Add((New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes', 'Attempt to update Az modules to the latest version'))
$UpdateModulesChoices.Add((New-Object System.Management.Automation.Host.ChoiceDescription -ArgumentList '&No', 'Use currently installed Az modules'))

$UpdateModulesDecision = Prompt-ForChoice -Title "Update Az Modules" `
                                           -Question "Do you want to update required Az Modules to the latest version?" `
                                           -Choices $UpdateModulesChoices `
                                           -DefaultChoice 1
$UpdateAzModules = $UpdateModulesDecision -eq 0

# Update Az modules if needed
Update-AzModulesIfNeeded -ShouldUpdate $UpdateAzModules

Write-Log -Message "Script initialization complete. Proceeding with main logic." -Severity "Information"

## If TenantId not supplied, prompt the user to select a tenant
if (-not $TenantId) {
    Write-Log -Message "TenantId not supplied. Retrieving available tenants..." -Severity "Information"

    $tenants = Get-AzTenant
    if ($tenants.Count -gt 1) {
        Write-Log -Message "Multiple tenants found. Prompting user to select one." -Severity "Information"

        $selectedTenant = $tenants | Out-ConsoleGridView -Title "Select Tenant" -OutputMode Single
        if (-not $selectedTenant) {
            Write-Log -Message "No tenant selected. Exiting..." -Severity "Error"
            exit
        }
        $TenantId = $selectedTenant.TenantId
        Write-Log -Message "Selected TenantId: $TenantId" -Severity "Information"
    } else {
        # Only one tenant found, use it automatically
        $TenantId = $tenants[0].TenantId
        Write-Log -Message "Only one tenant found. Using TenantId: $TenantId" -Severity "Information"
    }
}

Write-Log -Message "Connecting to Azure with TenantId: $TenantId" -Severity "Information"
Connect-AzAccount -Tenant $TenantId | Out-Null

# Retrieve subscriptions for the tenant
Write-Log -Message "Retrieving subscriptions for TenantId: $TenantId" -Severity "Information"
$subscriptions = Get-AzSubscription -TenantId $TenantId
if (-not $subscriptions) {
    Write-Log -Message "No subscriptions found for TenantId: $TenantId. Exiting..." -Severity "Error"
    exit
}

Write-Log -Message "Prompting user to select a subscription." -Severity "Information"
$selectedSubscription = $subscriptions | Select-Object Name, SubscriptionId, State |
    Out-ConsoleGridView -Title "Select Subscription" -OutputMode Single
if (-not $selectedSubscription) {
    Write-Log -Message "No subscription selected. Exiting..." -Severity "Error"
    exit
}
Write-Log -Message "Selected Subscription: $($selectedSubscription.Name) with SubscriptionId: $($selectedSubscription.SubscriptionId)" -Severity "Information"

# Set the context to the selected subscription
Write-Log -Message "Setting context to SubscriptionId: $($selectedSubscription.SubscriptionId)" -Severity "Information"
$null = Set-AzContext -SubscriptionId $selectedSubscription.SubscriptionId -Tenant $TenantId

# Retrieve resource groups for the selected subscription
Write-Log -Message "Retrieving resource groups for subscription: $($selectedSubscription.Name)" -Severity "Information"
$resourceGroups = Get-AzResourceGroup
if (-not $resourceGroups) {
    Write-Log -Message "No resource groups found in subscription: $($selectedSubscription.Name). Exiting..." -Severity "Error"
    exit
}

Write-Log -Message "Prompting user to select a resource group." -Severity "Information"
$selectedResourceGroup = $resourceGroups | Select-Object ResourceGroupName, Location | 
    Out-ConsoleGridView -Title "Select Resource Group" -OutputMode Single
if (-not $selectedResourceGroup) {
    Write-Log -Message "No resource group selected. Exiting..." -Severity "Error"
    exit
}
Write-Log -Message "Selected Resource Group: $($selectedResourceGroup.ResourceGroupName)" -Severity "Information"

# Retrieve Logic Apps in the selected resource group
Write-Log -Message "Retrieving Logic Apps in Resource Group: $($selectedResourceGroup.ResourceGroupName)" -Severity "Information"
$logicApps = Get-AzResource -ResourceGroupName $selectedResourceGroup.ResourceGroupName -ResourceType "Microsoft.Logic/workflows" -ExpandProperties
if (-not $logicApps) {
    Write-Log -Message "No Logic Apps found in Resource Group: $($selectedResourceGroup.ResourceGroupName). Exiting..." -Severity "Error"
    exit
}
Write-Log -Message "Found $($logicApps.Count) Logic App(s) in Resource Group: $($selectedResourceGroup.ResourceGroupName)" -Severity "Information"

# Prompt user to select one or multiple Logic Apps to export
Write-Log -Message "Prompting user to select Logic Apps for export." -Severity "Information"
$selectedLogicApps = $logicApps |
    Select-Object ResourceGroupName, Name, Location, @{Name='Kind';Expression={$_.Properties.kind}}, @{Name='State';Expression={$_.Properties.state}} |
    Out-ConsoleGridView -Title "Select Logic Apps to Export as ARM Templates (Press ENTER when done)"

if (-not $selectedLogicApps) {
    Write-Log -Message "No Logic Apps selected. Exiting..." -Severity "Error"
    exit
}
Write-Log -Message "User selected $($selectedLogicApps.Count) Logic App(s) for export." -Severity "Information"

# Setup variables for ARM template generation.
$armHostUrl = "https://management.azure.com"
$tokenToUse = (Get-AzAccessToken).Token
$PlaybookARMParameters = [ordered]@{}
$templateVariables = [ordered]@{}
$apiConnectionResources = New-Object System.Collections.Generic.List[Object]

# Function to fix JSON indentation for better readability.
Function FixJsonIndentation ($jsonOutput) {
    Try {
        $currentIndent = 0
        $tabSize = 4
        $lines = $jsonOutput.Split([Environment]::NewLine)
        $newString = ""
        foreach ($line in $lines) {
            if ($line.Trim() -eq "") {
                continue
            }

            # If line ends with ] or }, reduce indent first.
            if ($line -match "[\]\}],?\s*$") {
                $currentIndent -= 1
            }

            # Add current line with the right indent.
            if ($newString -eq "") {
                $newString = $line
            } else {
                $spaces = ""
                $matchFirstChar = [regex]::Match($line, '[^\s]+')
                $totalSpaces = $currentIndent * $tabSize
                if ($totalSpaces -gt 0) {
                    $spaces = " " * $totalSpaces
                }
                $newString += [Environment]::NewLine + $spaces + $line.Substring($matchFirstChar.Index)
            }

            # If line ends with { or [, increase indent.
            if ($line -match "[\[{]\s*$") {
                $currentIndent += 1
            }
        }
        return $newString
    }
    catch {
        Write-Log -Message "Error occurred in FixJsonIndentation :$($_)" -Severity Error
    }
}

# Function to build the full ARM resource ID for the playbook (logic app).
Function BuildPlaybookArmId() {
    Try {
        if ($PlaybookSubscriptionId -and $PlaybookResourceGroupName -and $PlaybookResourceName) {
            return "/subscriptions/$PlaybookSubscriptionId/resourceGroups/$PlaybookResourceGroupName/providers/Microsoft.Logic/workflows/$PlaybookResourceName"
        }
    }
    catch {
        Write-Log -Message "Playbook ARM id parameters are required: $($_)" -Severity Error
    }
}

# Function to send a GET call to ARM using REST.
Function SendArmGetCall($relativeUrl) {
    $authHeader = @{
        'Authorization'='Bearer ' + $tokenToUse
    }

    $absoluteUrl = $armHostUrl+$relativeUrl
    Try {
        $result = Invoke-RestMethod -Uri $absoluteUrl -Method Get -Headers $authHeader
        return $result
    }
    catch {
        Write-Log -Message $($_.Exception.Response.StatusCode.value__) -Severity Error
        Write-Log -Message $($_.Exception.Response.StatusDescription) -Severity Error
    } 
}

# Function to retrieve the playbook resource and adjust it for ARM template export.
Function GetPlaybookResource() {
    Try {    
        $playbookArmIdToUse = BuildPlaybookArmId
        $playbookResource = SendArmGetCall -relativeUrl "$($playbookArmIdToUse)?api-version=2017-07-01"

        # Add a parameter for the playbook name to the ARM template.
        $PlaybookARMParameters.Add("PlaybookName", [ordered] @{
            "defaultValue"= $playbookResource.Name
            "type"= "string"
        })

        # If generating for gallery, add specific tags, metadata, and ensure SystemAssigned identity.
        if ($GenerateForGallery) {
            if (!("tags" -in $playbookResource.PSobject.Properties.Name)) {
                Add-Member -InputObject $playbookResource -Name "tags" -Value @() -MemberType NoteProperty -Force
            }

            if (!$playbookResource.tags) {
                $playbookResource.tags = [ordered] @{
                    "hidden-SentinelTemplateName"= $playbookResource.name
                    "hidden-SentinelTemplateVersion"= "1.0"
                }
            }
            else {
                if (!$playbookResource.tags["hidden-SentinelTemplateName"]) {
                    Add-Member -InputObject $playbookResource.tags -Name "hidden-SentinelTemplateName" -Value $playbookResource.name -MemberType NoteProperty -Force
                }
                if (!$playbookResource.tags["hidden-SentinelTemplateVersion"]) {
                    Add-Member -InputObject $playbookResource.tags -Name "hidden-SentinelTemplateVersion" -Value "1.0" -MemberType NoteProperty -Force
                }
            }

            if ($playbookResource.identity.type -ne "SystemAssigned") {
                if (!$playbookResource.identity) {
                    Add-Member -InputObject $playbookResource -Name "identity" -Value @{
                        "type"= "SystemAssigned"
                    } -MemberType NoteProperty -Force
                }
                else {
                    $playbookResource.identity = @{
                        "type"= "SystemAssigned"
                    }
                }
            }
        }

        # Remove properties that are specific to an existing deployment and not needed for the template.
        $playbookResource.PSObject.Properties.remove("id")
        $playbookResource.location = "[resourceGroup().location]"
        $playbookResource.name = "[parameters('PlaybookName')]"
        Add-Member -InputObject $playbookResource -Name "apiVersion" -Value "2017-07-01" -MemberType NoteProperty
        Add-Member -InputObject $playbookResource -Name "dependsOn" -Value @() -MemberType NoteProperty

        $playbookResource.properties.PSObject.Properties.remove("createdTime")
        $playbookResource.properties.PSObject.Properties.remove("changedTime")
        $playbookResource.properties.PSObject.Properties.remove("version")
        $playbookResource.properties.PSObject.Properties.remove("accessEndpoint")
        $playbookResource.properties.PSObject.Properties.remove("endpointsConfiguration")

        if ($playbookResource.identity) {
            $playbookResource.identity.PSObject.Properties.remove("principalId")
            $playbookResource.identity.PSObject.Properties.remove("tenantId")
        }

        return $playbookResource
    }
    Catch {
        Write-Log -Message "Error occurred in GetPlaybookResource :$($_)" -Severity Error
    }
}

# Function to handle API connection references in the logic app definition,
# converting them to ARM template compatible resources and parameters.
Function HandlePlaybookApiConnectionReference($apiConnectionReference, $playbookResource) {
    Try {
        $connectionName = $apiConnectionReference.Name
        $connectionName = $connectionName.Split('_')[0].ToString().Trim()
        $connectionName = (Get-Culture).TextInfo.ToTitleCase($connectionName)

        if ($connectionName -ieq "azuresentinel") {
            $connectionVariableName = "MicrosoftSentinelConnectionName" 
            $templateVariables.Add($connectionVariableName, "[concat('MicrosoftSentinel-', parameters('PlaybookName'))]")           
        } else {
            $connectionVariableName = "$($connectionName)ConnectionName"
            $templateVariables.Add($connectionVariableName, "[concat('$connectionName-', parameters('PlaybookName'))]")
        }

        $connectorType = if ($apiConnectionReference.Value.id.ToLowerInvariant().Contains("/managedapis/")) { "managedApis" } else { "customApis" } 
        $connectionAuthenticationType = if ($apiConnectionReference.Value.connectionProperties.authentication.type -eq "ManagedServiceIdentity") { "Alternative" } else { $null }    

        # If generating for gallery and the connection is azuresentinel, convert to MSI if not already.
        if ($GenerateForGallery -and $connectionName -eq "azuresentinel" -and !$connectionAuthenticationType) {
            $connectionAuthenticationType = "Alternative"
            if (!$apiConnectionReference.Value.ConnectionProperties) {
                Add-Member -InputObject $apiConnectionReference.Value -Name "ConnectionProperties" -Value @{} -MemberType NoteProperty
            }
            $apiConnectionReference.Value.connectionProperties = @{
                "authentication"= @{
                    "type"= "ManagedServiceIdentity"
                }
            }
        }

        # Try to retrieve the existing connection and connector properties from ARM.
        try {
            $existingConnectionProperties = SendArmGetCall -relativeUrl "$($apiConnectionReference.Value.connectionId)?api-version=2016-06-01"
        }
        catch {
            $existingConnectionProperties = $null
        }

        $existingConnectorProperties = SendArmGetCall -relativeUrl "$($apiConnectionReference.Value.id)?api-version=2016-06-01"

        # Create the API connection resource entry for the ARM template.
        $apiConnectionResource = [ordered] @{
            "type"= "Microsoft.Web/connections"
            "apiVersion"= "2016-06-01"
            "name"= "[variables('$connectionVariableName')]"
            "location"= "[resourceGroup().location]"
            "kind"= "V1"
            "properties"= [ordered] @{
                "displayName"= "[variables('$connectionVariableName')]"
                "customParameterValues"= [ordered] @{}
                "parameterValueType"= $connectionAuthenticationType
                "api"= [ordered] @{
                    "id"= "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/$connectorType/$connectionName')]"
                }
            }
        }

        # If no parameterValueType needed, remove it.
        if (!$apiConnectionResource.properties.parameterValueType) {
            $apiConnectionResource.properties.Remove("parameterValueType")
        }

        # Add the constructed API connection resource to the list of resources.
        $apiConnectionResources.Add($apiConnectionResource) | Out-Null

        # Update the connection reference in the playbook resource to ARM template variables.
        $apiConnectionReference.Value = [ordered] @{
            "connectionId"= "[resourceId('Microsoft.Web/connections', variables('$connectionVariableName'))]"
            "connectionName" = "[variables('$connectionVariableName')]"
            "id" = "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/$connectorType/$connectionName')]"
            "connectionProperties" = $apiConnectionReference.Value.connectionProperties
        }

        # If no connectionProperties, remove the property from the reference.
        if (!$apiConnectionReference.Value.connectionProperties) {
            $apiConnectionReference.Value.Remove("connectionProperties")
        }

        # Add dependency on the newly created API connection resource.
        $playbookResource.dependsOn += "[resourceId('Microsoft.Web/connections', variables('$connectionVariableName'))]"
    }
    Catch {
        Write-Log -Message "Error occurred in HandlePlaybookApiConnectionReference :$($_)" -Severity Error
    }
}

# Function to build the final ARM template for the playbook,
# including parameters, variables, and resources.
Function BuildArmTemplate($playbookResource) {
    Try {
        $armTemplate = [ordered] @{
            '$schema' = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
            "contentVersion"= "1.0.0.0"
            "parameters"= $PlaybookARMParameters
            "variables"= $templateVariables
            "resources"= @($playbookResource)+$apiConnectionResources
        }

        # If generating for the gallery, insert additional metadata.
        if ($GenerateForGallery) {
            $armTemplate.Insert(2, "metadata", [ordered] @{
                "title"= ""
                "description"= ""
                "prerequisites"= ""
                "postDeployment" = @()
                "prerequisitesDeployTemplateFile"= ""
                "lastUpdateTime"= ""
                "entities"= @()
                "tags"= @()
                "support"= [ordered] @{
                    "tier"= "community"
                    "armtemplate" = "Generated"
                }
                "author"= @{
                    "name"= ""
                }
            })
        }

        return $armTemplate
    }
    Catch {
        Write-Log -Message "Error occurred in BuildArmTemplate :$($_)" -Severity Error
    }
}

Write-Log "Exporting selected Logic Apps as ARM templates..."

# Export each selected Logic App as an ARM template.
foreach ($app in $selectedLogicApps) {
    $rg = $app.ResourceGroupName
    $name = $app.Name

    # Retrieve subscription, RG, and name for the ARM template build.
    $PlaybookSubscriptionId = $selectedSubscription.SubscriptionId
    $PlaybookResourceGroupName = $rg
    $PlaybookResourceName = $name

    # Clear parameters and resources for each new ARM template to avoid contamination.
    $PlaybookARMParameters.Clear()
    $templateVariables.Clear()
    $apiConnectionResources.Clear()

    # Get the playbook resource in a form suitable for ARM template export.
    $playbookResource = GetPlaybookResource
    if ($null -eq $playbookResource) {
        Write-Log "Could not build ARM template for '$name'. Skipping..." -Severity Error
        continue
    }

    # Check for API connections and handle them if present.
    $apiConnectionsReferences = $playbookResource.properties.definition?.resources?.actions | Where-Object { $_.value?.type -eq 'ApiConnection' }
    if ($apiConnectionsReferences) {
        foreach ($connRef in $apiConnectionsReferences) {
            HandlePlaybookApiConnectionReference -apiConnectionReference $connRef -playbookResource $playbookResource
        }
    }

    # Build the ARM template JSON.
    $armTemplate = BuildArmTemplate $playbookResource
    $armTemplateJson = ($armTemplate | ConvertTo-Json -Depth 50)
    $armTemplateJson = FixJsonIndentation $armTemplateJson

    # Export the ARM template to the chosen folder.
    $armFileName = Join-Path $exportFolder "$($name)_ARM.json"
    try {
        $armTemplateJson | Out-File -FilePath $armFileName -Encoding UTF8
        Write-Log "Exported ARM Template for '$name' to '$armFileName'" -Severity Information
    } catch {
        Write-Log "Failed to export ARM Template for '$name': $($_.Exception.Message)" -Severity Error
    }
}

Write-Log "Export complete. Check the 'Exports' folder for the ARM template files." -Severity Information
