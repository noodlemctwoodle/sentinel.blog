# Required Modules
$requiredModules = @("Az.Accounts", "Az.OperationalInsights", "Az.SecurityInsights")

# Script Synopsis and Description
<#
    .Synopsis
        This script retrieves all open Sentinel incidents, groups them by month, and exports the total number of incidents per month to a CSV file.

    .DESCRIPTION
        This PowerShell script checks for the availability of required Azure modules ("Az.Accounts", "Az.OperationalInsights", "Az.SecurityInsights") and installs them if not available. The script connects to Azure Account, retrieves Azure subscriptions, and extracts incidents from Sentinel-enabled Log Analytics workspaces. It aggregates these incidents by their creation month and exports the count per month to a CSV file.

    .EXAMPLE
        PS> .\Export-IncidentsByMonth.ps1
        This example demonstrates how to run the script from the PowerShell command line.

    .INPUTS
        None. No input is required to run this script.

    .OUTPUTS
        CSV file. The script generates a CSV file containing the count of open Sentinel incidents by month.

    .NOTES
        Requires administrator privileges for module installation.

    .COMPONENT
        Azure Accounts, Azure Operational Insights, Azure Security Insights

    .ROLE
        Useful for Microsoft Sentinel Contributors for monitoring and auditing.

    .FUNCTIONALITY
        Fetches and exports details of open Sentinel incidents by month across Azure subscriptions.
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

# Establish connection with Azure Account while suppressing any warnings
Connect-AzAccount -WarningAction SilentlyContinue

# Define the file path for the CSV output and the log file
$OutputFile = "C:\Temp\OpenIncidentsByMonthUTC.csv"
$LogFile = "C:\Temp\ScriptLog.txt"

# Initialize a hashtable to keep track of incidents per month
$incidentCountsByMonth = @{}

# Initialize an array to store the final output objects
$finalOutput = @()

# Function to add a log entry
function Write-Log {
    param(
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File $LogFile -Append
}

# Define subscription to client name mapping
$subscriptionToClientName = @{
    "b7bd67e6-73ee-42c6-9922-547a3da4e98a" ="Customer1"
    "b7bd67e6-73ee-42c6-9922-547a3da4e98b" = "Customer2"
    "b7bd67e6-73ee-42c6-9922-547a3da4e98c" = "Customer3"
    "b7bd67e6-73ee-42c6-9922-547a3da4e98d" = "Customer4"
}

function processWorkspace {
    param(
        [PSCustomObject]$Workspace, # Parameter to receive the workspace that will be processed
        [string]$ClientName # Parameter to receive the client name
    )

    Write-Log "Processing Workspace: $($Workspace.Name) for $ClientName"

    # Calculate the first and last day of the previous month in UTC
    $today = (Get-Date).ToUniversalTime()
    $firstDayOfThisMonth = (Get-Date -Year $today.Year -Month $today.Month -Day 1 -Hour 0 -Minute 0 -Second 0 -Millisecond 0).ToUniversalTime()
    $firstDayOfLastMonth = $firstDayOfThisMonth.AddMonths(-1)
    $lastDayOfLastMonth = $firstDayOfThisMonth.AddSeconds(-1)

    Write-Log "Date range for incidents: $firstDayOfLastMonth to $lastDayOfLastMonth"

    # Establish a connection with the Sentinel workspace
    $sentinelConnection = @{
        ResourceGroupName = $Workspace.ResourceGroupName
        WorkspaceName     = $Workspace.Name
    }

    # Fetch Sentinel incidents from the last month which are not closed
    $Incidents = Get-AzSentinelIncident @sentinelConnection `
    | Where-Object {$_.Status -ne "Closed" -and $_.CreatedTimeUTC -ge $firstDayOfLastMonth -and $_.CreatedTimeUTC -le $lastDayOfLastMonth} `
    | Select-Object -Property CreatedTimeUTC, Title, Severity, Status, Number, OwnerAssignedTo, @{Name='Workspace';Expression={$Workspace.Name}}, @{Name='ResourceGroup';Expression={$Workspace.ResourceGroupName}}, Resource 

    Write-Log "Fetched $($Incidents.Count) incidents from Workspace: $($Workspace.Name)"

    # Aggregate incidents by month and store details
    foreach ($incident in $Incidents) {
        $incidentMonth = $lastDayOfLastMonth.ToString("MM-yyyy")

        # Check if the month already has an entry in the hashtable
        if (-not $incidentCountsByMonth.ContainsKey($incidentMonth)) {
            $incidentCountsByMonth[$incidentMonth] = @()
        }

        # Create a custom object with the required details
        $incidentDetails = [PSCustomObject]@{
            Month         = $incidentMonth
            OpenIncidents = 1
            Workspace     = $Workspace.Name
            ResourceGroup = $Workspace.ResourceGroupName
            ClientName    = $ClientName
        }

        # Add the details object to the array for the corresponding month
        $incidentCountsByMonth[$incidentMonth] += $incidentDetails
    }
}

# Process each Azure subscription
foreach ($subscriptionId in $subscriptionToClientName.Keys) {
    $clientName = $subscriptionToClientName[$subscriptionId]
    Write-Log "Processing Subscription: $subscriptionId for $clientName"
    Set-AzContext -Subscription $subscriptionId -WarningAction SilentlyContinue

    $workspaces = Get-AzOperationalInsightsWorkspace -WarningAction SilentlyContinue
    Write-Log "Retrieved Workspaces for Subscription: $subscriptionId"

    $sentinelWs = $workspaces | Where-Object {
        (Get-AzOperationalInsightsIntelligencePacks -WarningAction SilentlyContinue -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.Name).Where({$_.Name -eq "SecurityInsights" -and $_.Enabled -eq $true})
    }

    if($sentinelWs -is [System.Collections.ICollection]) {
        foreach ($workspace in $sentinelWs) {
            processWorkspace -Workspace $workspace -ClientName $clientName
        }
    } else {
        processWorkspace -Workspace $sentinelWs -ClientName $clientName
    }
}

# Flatten the list of incidents per month into a single list for export
$finalOutput = foreach ($month in $incidentCountsByMonth.Keys) {
    $monthIncidents = $incidentCountsByMonth[$month] | Group-Object Month, Workspace, ResourceGroup, ClientName | ForEach-Object {
        # Sum up the incidents for each group
        [PSCustomObject]@{
            Month         = $_.Name.Split(',')[0].Trim()
            Workspace     = $_.Name.Split(',')[1].Trim()
            ClientName    = $_.Name.Split(',')[3].Trim()
            OpenIncidents = ($_.Group | Measure-Object OpenIncidents -Sum).Sum
        }
    }
    $monthIncidents
}

# Export the final output to a CSV file
$finalOutput | Export-Csv $OutputFile -NoTypeInformation -Force
Write-Log "Exported incident counts to CSV with custom format."

# Final log entry
Write-Log "Script execution completed."
