<#
#Requires -Version 7
#Requires -Modules Az.Accounts
#Requires -Modules Az.Resources
#Requires -Modules Az.SecurityInsights
#Requires -Modules Microsoft.PowerShell.ConsoleGuiTools
#>

<#
.DESCRIPTION
This script can be used to bulk close multiple incidents in Microsoft Sentinel using PowerShell Core interaction menus.

The default incident count is 1000. An int32 value up to 2,147,483,647 can be set using -IncidentCount

Incident closure comments can be ammended to fit purpose starting on line 333.

.EXAMPLE
.\Close-SentinelIncidents.ps1 -TenantId "<String>"
.\Close-SentinelIncidents.ps1 -TenantId "<String>" -IncidentCount "<Int32>"
.\Close-SentinelIncidents.ps1 -TenantId "<String>" -StartDate "<DateTime>" -EndDate "<DateTime>"
.\Close-SentinelIncidents.ps1 -SubscriptionId "<String>" -StartDate "<DateTime>" -EndDate "<DateTime>"

.NOTES
  Version:          1.1
  Author:           noodlemctwoodle
  Creation Date:    07/03/2023

.LINK
https://docs.microsoft.com/en-us/powershell/module/az.securityinsights/?view=azps-7.1.0#security-insights
https://github.com/PowerShell/PowerShell/releases
#>

param (
    [parameter(Position = 0, Mandatory = $false, HelpMessage = 'Enter your Tenant Id')]
    [string] $TenantId,
    [parameter(Position = 0, Mandatory = $false, HelpMessage = 'Enter your Tenant Id')]
    [string] $SubscriptionId,
    [parameter(Position = 1, Mandatory = $false, HelpMessage = 'Enter the total amount of incidents to generate (Int32)')]
    [string] $IncidentCount,
    [parameter(Position = 2, Mandatory = $false, HelpMessage = 'Enter the start date in this format "01/01/2022 00:00"')]
    [string] $StartDate,
    [parameter(Position = 3, Mandatory = $false, HelpMessage = 'Enter the end date in this format "01/31/2022 23:59"')]
    [string] $EndDate
)

# Create direct link to PowerShell 7 download MSI.
$PowerShell7 = "https://github.com/PowerShell/PowerShell/releases"

# Create $LogFileName for Write-Log function.
$TimeStamp = Get-Date -Format ddMMyyy_HHmm
$LogFileName = '{0}_{1}.csv' -f "Sentinel_Incidents_Log", $TimeStamp

$SelectedStartDate = [datetime]$StartDate
$SelectedEndDate = [datetime]$EndDate

function Write-Log {
    <#
        .DESCRIPTION
        Write-Log is used to write information to a log file and to the console.

        .PARAMETER Severity
        parameter specifies the severity of the log message. Values can be: Information, Warning, or Error.
        #>

    [CmdletBinding()]
    param(
        [parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [string]$LogFileName,

        [parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information', 'Warning', 'Error', 'Wait')]
        [string]$Severity = ('Information', 'Warning', 'Error', 'Wait')
    )
    # Write the message out to the correct channel
    switch ($Severity) {
        "Information" { Write-Host $Message -ForegroundColor Green }
        "Warning" { Write-Host $Message -ForegroundColor Yellow }
        "Error" { Write-Host $Message -ForegroundColor Red }
        "Wait" { Write-Host $Message -ForegroundColor Cyan }
    }
    try {
        [PSCustomObject]@{
            Time     = (Get-Date -Format g)
            Message  = $Message
            Severity = $Severity
        } | Export-Csv -Path "$PSScriptRoot\$LogFileName" -Append -NoTypeInformation -Force
    }
    catch {
        Write-Error "An error occurred in Write-Log() method" -ErrorAction SilentlyContinue
    }
}

function Get-RequiredModules {
    <#
        .DESCRIPTION
        Get-Required is used to install and then import a specified PowerShell module.

        .PARAMETER Module
        parameter specifices the PowerShell module to install.
        #>

    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)] $Module
    )

    try {
        $installedModule = Get-InstalledModule -Name $Module -ErrorAction SilentlyContinue

        if ($null -eq $installedModule) {
            Write-Log -Message "The $Module PowerShell module was not found" -LogFileName $LogFileName -Severity Warning
            # Check for Admin Privleges.
            $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

            if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                # Not an Admin, install to current user.
                Write-Log -Message "Cannot install the $Module module. You are not running as Administrator" -LogFileName $LogFileName -Severity Warning
                Write-Log -Message "Installing $Module module to current user Scope" -LogFileName $LogFileName -Severity Warning

                Install-Module -Name $Module -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
                Import-Module -Name $Module -Force
            }
            else {
                # Admin, install to all users.
                Write-Log -Message "Installing the $Module module to all users" -LogFileName $LogFileName -Severity Warning
                Install-Module -Name $Module -Repository PSGallery -Force -AllowClobber
                Import-Module -Name $Module -Force
            }
        }
        else {
            if ($UpdateAzModules) {
                Write-Log -Message "Checking updates for module $Module" -LogFileName $LogFileName -Severity Information
                $currentVersion = [Version](Get-InstalledModule | Where-Object { $_.Name -eq $Module }).Version
                # Get latest version from gallery.
                $latestVersion = [Version](Find-Module -Name $Module).Version
                if ($currentVersion -ne $latestVersion) {
                    # Check for Admin Privleges.
                    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

                    if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
                        # Install to current user.
                        Write-Log -Message "Can not update the $Module module. You are not running as Administrator" -LogFileName $LogFileName -Severity Warning
                        Write-Log -Message "Updating $Module from [$currentVersion] to [$latestVersion] to current user Scope" -LogFileName $LogFileName -Severity Warning
                        Update-Module -Name $Module -RequiredVersion $latestVersion -Force
                    }
                    else {
                        # Admin - Install to all users.
                        Write-Log -Message "Updating $Module from [$currentVersion] to [$latestVersion] to all users" -LogFileName $LogFileName -Severity Warning
                        Update-Module -Name $Module -RequiredVersion $latestVersion -Force
                    }
                }
                else {
                    # Get latest version.
                    $latestVersion = [Version](Get-Module -Name $Module).Version
                    Write-Log -Message "Importing module $Module with version $latestVersion" -LogFileName $LogFileName -Severity Information
                    Import-Module -Name $Module -RequiredVersion $latestVersion -Force
                }
            }
            else {
                # Get latest version.
                $latestVersion = [Version](Get-Module -Name $Module).Version
                Write-Log -Message "Importing module $Module with version $latestVersion" -LogFileName $LogFileName -Severity Information
                Import-Module -Name $Module -RequiredVersion $latestVersion -Force
            }
        }
        # Install-Module will obtain the module from the gallery and install it on your local machine, making it available for use.
        # Import-Module will bring the module and its functions into your current powershell session, if the module is installed.
    }
    catch {
        Write-Log -Message "An error occurred in Get-RequiredModules() method - $($_)" -LogFileName $LogFileName -Severity Error
    }
}

Get-RequiredModules("Az.Accounts")
Get-RequiredModules("Az.OperationalInsights")
Get-RequiredModules("Az.Resources")
Get-RequiredModules("Az.SecurityInsights")
Get-RequiredModules("Microsoft.PowerShell.ConsoleGuiTools")

# Check Powershell version, needs to be 7 or higher.
if ($host.Version.Major -lt 7) {
    Write-Log "Supported PowerShell version for this script is 7 or above. Download $PowerShell7" -LogFileName $LogFileName -Severity Error
    exit
}

# Disconnect exiting connections and clearing contexts.
Write-Log "Clearing existing Azure connection" -LogFileName $LogFileName -Severity Information
$null = Disconnect-AzAccount -ContextName 'MyAzContext' -ErrorAction SilentlyContinue
Write-Log "Clearing existing Azure context" -LogFileName $LogFileName -Severity Information

Get-AzContext -ListAvailable | ForEach-Object { $_ | Remove-AzContext -Force -Verbose | Out-Null } #remove all connected content
Write-Log "Clearing of existing connection and context completed." -LogFileName $LogFileName -Severity Information

try {
    function Get-OSVersion {
        <#
        .DESCRIPTION
        Get-OSVersion is used to capture the OS Version you are using.
        #>

        $OSType = $PSVersionTable | Select-Object OS
        if ($OSType -like "*Microsoft Windows*") {
            Connect-AzAccount -Subscription $SubscriptionId -ContextName 'MyAzContext' -Force -ErrorAction Stop
        }
        if ($OSType -like "*Linux*") {
            Connect-AzAccount -UseDeviceAuthentication
        }
        else {

        }
    }

    Get-OSVersion

    # Select and set Azure subscription where Microsoft Sentinel is located.
    $GetSubscriptions = Get-AzSubscription -TenantId $TenantId | Where-Object { ($_.state -eq 'enabled') } | Out-ConsoleGridView -Title "Select Subscription to Use" -OutputMode Single

    Set-AzContext $GetSubscriptions

    Write-Log -Message "Setting AzContext to $GetSubscriptions" -LogFileName $LogFileName -Severity Information
}
catch {
    Write-Log "Error When trying to connect to tenant : $($_)" -LogFileName $LogFileName -Severity Error
    exit
}

try {
    # Select and set the resource group where Sentinel is located.
    $ResourceGroup = Get-AzResourceGroup | Select-Object -Expand ResourceGroupName | Out-ConsoleGridView -Title "Select Resouce Group to use" -OutputMode Single

    Write-Log -Message "Capturing Azure Resource Group name" -LogFileName $LogFileName -Severity Information

    # Select and set the Workspace where Microsoft Sentinel is located.
    $WorkspaceName = Get-AzResource -ResourceGroupName $ResourceGroup | Where-Object ResourceType -eq "Microsoft.OperationalInsights/workspaces" `
    | Select-Object -Expand Name | Out-ConsoleGridView -Title "Select Sentinel Workspace to use" -OutputMode Single

    Write-Log -Message "Capturing Azure Log Analytics Workspace name" -LogFileName $LogFileName -Severity Information

}
catch {
    Write-Log "Error When trying to connect to tenant" -LogFileName $LogFileName -Severity Error
    exit
}

try {
    # Create Microsoft Sentinel connection string used for Close-Incident Function.
    $SentinelConnection = @{
        ResourceGroupName = $ResourceGroup
        WorkspaceName     = $WorkspaceName
    }

    Write-Log -Message "Creating Sentinel Connection for Close-Incident Function" -LogFileName $LogFileName -Severity Information
}
catch {
    Write-Log "Error creating Sentinel Connection for Close-Incident Function : $($_)" -LogFileName $LogFileName -Severity Error
    exit
}

# Exit script if no if Microsfot Sentinel connection string is not set.
if ( $null -eq $SentinelConnection) {
    Write-Log  "Sentinel connection string not found, script exiting..." -Severity Error
    break
}

try {
    # Capture UserPrincipalName from AzContext and store in $IncidentOwner variable, this is used to assign the incident owner.
    $IncidentOwner = Get-Azcontext | Select-Object Account
    Write-Log -Message "Capturing UserPrincipalName: $IncidentOwner from AzContext" -LogFileName $LogFileName -Severity Information
}

catch {
    Write-Log "Error Capturing UserPrincipalName : $($_)" -LogFileName $LogFileName -Severity Error
    exit
}

Clear-Host

try {
    Write-Log -Message "Generating list of incidents. Please wait..." -LogFileName $LogFileName -Severity Wait

    # Select incidents to close from interactive selction and save it to $Incidents.
    if ($null -ne $StartDate) {
        $Incidents = Get-AzSentinelIncident @SentinelConnection -Top 1000 `
        | Where-Object { ($_.CreatedTimeUtc -ge $SelectedStartDate -and $_.CreatedTimeUtc -lt $SelectedEndDate) -and ($_.Status -ne "Closed") } `
        | Select-Object CreatedTimeUTC, Title, IncidentNumber, Severity, Status, Name `
        | Sort-Object -Property CreatedTimeUTC `
        | Out-ConsoleGridView -Title "Select incidents to close"
    }

    elseif ($null -ne $IncidentCount) {
        # The optional parameter $IncidentCount was not set generating a list of 1000 incidents.
        $Incidents = Get-AzSentinelIncident @SentinelConnection -Top 1000 `
        | Where-Object Status -ne "Closed" `
        | Select-Object -property CreatedTimeUTC, Title, IncidentNumber, Severity, Status, Name `
        | Sort-Object -Property CreatedTimeUTC -Descending `
        | Out-ConsoleGridView -Title "Select incidents to close"
    }
  
    else {
        # The optional parameter $IncidentCount was set generating a list of specified incidents.
        $Incidents = Get-AzSentinelIncident @SentinelConnection -Top $IncidentCount `
        | Where-Object Status -ne "Closed" `
        | Select-Object -property CreatedTimeUTC, Title, IncidentNumber, Severity, Status, Name `
        | Sort-Object -Property CreatedTimeUTC -Descending `
        | Out-ConsoleGridView -Title "Select incidents to close"
    }

    Write-Log -Message "Capturing incidents from interactive selection menu" -LogFileName $LogFileName -Severity Information

}

catch {
    Write-Log "Error capturing Sentinel incident : $($_)" -LogFileName $LogFileName -Severity Error
    exit
}

try {
    # Exit script if no incidents were captured in $Incidents, script cannot contine with $null selection.
    if ( $null -eq $Incidents ) {
        Write-Log  "You have not selected any incidents, script exiting..." -Severity Error
        break
    }
}
catch {
    Write-Log "Error capturing Sentinel incident selection : $($_)" -LogFileName $LogFileName -Severity Error
    exit
}

try {
    # Create Microsoft Sentinel closure string used in Close-Incident function.
    $SelectIncidentClassification = @{
        BenignPositive = "SuspiciousButExpected"
        FalsePositive  = "IncorrectAlertLogic"
        TruePositive   = "SuspiciousActivity"
        Undetermined   = "Undetermined"
    }

    Write-Log -Message "Create closure string classification for Close-Incident function" -LogFileName $LogFileName -Severity Information

}
catch {
    Write-Log "Error capturing closure code of incident : $($_)" -LogFileName $LogFileName -Severity Error
    exit
}

try {
    # Select incident closure string from interactive selection and save to $IncidentClassification variable.
    $IncidentClassification = $SelectIncidentClassification `
    | Out-ConsoleGridView -Title "Select Classification Reason" -OutputMode Single

    Write-Log -Message "Capturing classification reason from interactive session" -LogFileName $LogFileName -Severity Information
}
catch {
    Write-Log "Error capturing Sentinel incident : $($_)" -LogFileName $LogFileName -Severity Error
    exit
}

try {
    # Select a comment to close the incidents, these can be ammended to fit purpose.
    $ClosureComment = `
        "Incident investigated and closed using Close-SentinelIncidents.ps1", `
        "Incidents investigated and closed using Close-SentinelIncidents.ps1", `
        "Batch closed multiple incidents that have previously been investgated using Close-SentinelIncidents.ps1", `
        "Closed all incidents in TP-Workspace as we have now migrated to a new subscription and Sentinel Workspace. (noodlemctwoodle)" `
    | Out-ConsoleGridView -Title "Select Classification Comment" -OutputMode Single

    Write-Log -Message "Capturing incident comment" -LogFileName $LogFileName -Severity Information

}
catch {
    Write-Log "Error capturing incident comment: $($_)" -LogFileName $LogFileName -Severity Error
    exit
}

try {
    function Close-Incident {
        <#
        .DESCRIPTION
        Close-Incident is used to close the incident based on previous selections in
        $IncidentClassification.Name, $IncidentClassification.Value, $SelectIncidentClassification, $ClosureComment.
        #>

        if ($IncidentClassification.Name -eq "Undetermined") {
            $Incidents | ForEach-Object `
            {
                $IncidnetId = $_.Name
                Update-AzSentinelIncident @SentinelConnection `
                    -Id $_.Name `
                    -Title $_.Title `
                    -Severity $_.Severity `
                    -Status Closed `
                    -OwnerAssignedTo "Sentinel Notifications" `
                    -OwnerUserPrincipalName "user.name@tld.com" `
                    -Classification $IncidentClassification.Value `
                    -ClassificationComment $ClosureComment `
                    -Confirm:$false
            }
        }
        else {
            $Incidents | ForEach-Object `
            {
                $IncidnetId = $_.Name
                Update-AzSentinelIncident @SentinelConnection `
                    -Id $_.Name `
                    -Title $_.Title `
                    -Severity $_.Severity `
                    -Status Closed `
                    -OwnerAssignedTo "Sentinel Notifications" `
                    -OwnerUserPrincipalName "user.name@tld.com" `
                    -Classification $IncidentClassification.Name `
                    -ClassificationReason $IncidentClassification.Value  `
                    -ClassificationComment $ClosureComment `
                    -Confirm:$false
            }
        }

    }

    Write-Log -Message "Caputiring incidents to close in Close-Incident function" -LogFileName $LogFileName -Severity Information
}
catch {

    Write-Log "Error Running Close-Incidents function : $($_)" -LogFileName $LogFileName -Severity Error
    exit
}

try {
    # Execute Close-Incident function to close incidents.
    Close-Incident

    Write-Log -Message "Running Close-Incidents function based $SelectIncidentClassification selection" -LogFileName $LogFileName -Severity Information

    # Write closed incidents to log file for auditing.
    $Incidents | ForEach-Object `
    {
        $IncidentTitle = $_.Title
        $IncidentNumber = $_.IncidentNumber

        Write-Log -Message "Closed Incdent $IncidentNumber - $IncidentTitle"  -LogFileName $LogFileName -Severity Information
    }
}
catch {
    Write-Log "Error closing incidents : $($_)" -LogFileName $LogFileName -Severity Error
    exit
}