# Required Modules
$requiredModules = @("Az.Accounts", "Az.OperationalInsights", "Az.SecurityInsights")

<#
    .Synopsis
        This script retrieves all open Sentinel incidents older than 90 days across all Azure subscriptions and exports them to a CSV file.

    .DESCRIPTION
        This PowerShell script checks the availability of required Azure modules ("Az.Accounts", "Az.OperationalInsights", "Az.SecurityInsights") in the system and installs them if they are not available. It assumes that the user has administrator privileges for installation.
        After ensuring the availability of the modules, it establishes a connection with Azure Account and retrieves all Azure subscriptions, extracting their Id and TenantId attributes.
        For each Azure subscription, it retrieves all Log Analytics workspaces, filtering those which have the Sentinel (SecurityInsights) solution enabled. For each filtered workspace, it fetches the Sentinel incidents which are not closed and were created over 90 days ago, sorting them in descending order by their creation time.
        Finally, it exports the fetched incidents into a CSV file located at "C:\Temp\OpenIncidents.csv".
    .EXAMPLE
        PS> .\Export-OpenIncidents.ps1
        This example demonstrates how to run the script from the PowerShell command line.
    .INPUTS
        None. You don't need to provide any input to run this script.
    .OUTPUTS
        CSV file. The script generates a CSV file ("C:\Temp\OpenIncidents.csv") containing information about open Sentinel incidents older than 90 days across all Azure subscriptions.
    .NOTES
        The script requires the user to have administrator privileges for the installation of the Azure modules.
    .COMPONENT
        This script leverages the following Azure components:
        Azure Accounts
        Azure Operational Insights
        Azure Security Insights
    .ROLE
        This script is intended for use by Microsoft Sentinel Contributors for monitoring and auditing purposes.
    .FUNCTIONALITY
        The script provides the ability to fetch and export details of open Sentinel incidents across all Azure subscriptions.
#>



foreach ($module in $requiredModules) {
    if (-not(Get-Module -ListAvailable -Name $module)) {
        # Check if user is an administrator
        $userIsAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if ($userIsAdministrator) {
            try {
                # Install the module
                Install-Module -Name $module -Scope CurrentUser -Force
            } catch {
                Write-Error "Failed to install module $module"
                return
            }
        } else {
            Write-Error "User must have administrator privileges to install module $module"
            return
        }
    }
}

# Define the file path for the CSV output
$OutputFile = "C:\Temp\OpenIncidents.csv"

# Establish connection with Azure Account while suppressing any warnings
Connect-AzAccount -WarningAction SilentlyContinue

# Retrieve all Azure subscriptions and extract their Id and TenantId attributes, suppressing any warnings
$subscriptions = @(Get-AzSubscription -WarningAction SilentlyContinue | Select-Object -Property Id, TenantId)  

# Create a function to process and handle the Sentinel workspace
function processWorkspace {
    param(
        $Workspace # Parameter to receive the workspace that will be processed
    )
    
    # Establish a connection with the Sentinel workspace using the Workspace name and Resource Group name
    $sentinelConnection = @{
        ResourceGroupName = $Workspace.ResourceGroupName
        WorkspaceName     = $Workspace.Name
    }

    # Fetch Sentinel incidents from the current workspace which are not closed and were created over 90 days ago,
    $Incidents = Get-AzSentinelIncident @sentinelConnection `
    | Where-Object {$_.Status -ne "Closed" -and $_.CreatedTimeUTC -lt (Get-Date).AddDays(-91)} `
    | Select-Object -property CreatedTimeUTC, Title, Severity, Status, Number, OwnerAssignedTo, @{Name='Workspace';Expression={$Workspace.Name}}, @{Name='ResourceGroup';Expression={$Workspace.ResourceGroupName}}, Resource `
    # Sort these incidents in descending order by their creation time, and select the necessary incident details
    | Sort-Object -Property CreatedTimeUTC -Descending  

    # Export the fetched incidents into a CSV file
    $Incidents | Export-Csv $OutputFile -NoTypeInformation -Append -Force
}

# Process each Azure subscription
foreach ($subscription in $subscriptions) {
    # Switch to the context of the current subscription, suppressing any warnings
    Set-AzContext -Subscription $subscription.Id -WarningAction SilentlyContinue

    # Retrieve all Log Analytics workspaces within the current subscription context, suppressing any warnings
    $workspaces = Get-AzOperationalInsightsWorkspace -WarningAction SilentlyContinue

    # Filter out the workspaces to only include those with the Sentinel (SecurityInsights) solution enabled
    $sentinelWs = $workspaces | Where-Object {
        (Get-AzOperationalInsightsIntelligencePacks -WarningAction SilentlyContinue -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.Name).Where({$_.Name -eq "SecurityInsights" -and $_.Enabled -eq $true})
    }

    # If the filtered workspaces are a collection, process each workspace individually; otherwise, process the single workspace
    if($sentinelWs -is [System.Collections.ICollection]) {
        foreach ($workspace in $sentinelWs) {
            processWorkspace -Workspace $workspace
        }
    } else {
        processWorkspace -Workspace $sentinelWs
    }
}