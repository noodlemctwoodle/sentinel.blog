<#
.EXAMPLE
.\Close-SentinelIncidentsSimple.ps1 -ResourceGroupName "<string>" -WorkspaceName "<string>" -ClassificationComment "<string>"

.NOTES
  Version:          0.2
  Author:           noodlemctwoodle
  Creation Date:    05/04/2023

.LINK
https://docs.microsoft.com/en-us/powershell/module/az.securityinsights/?view=azps-7.1.0#security-insights
#>


param (
    [parameter(Position = 0, Mandatory = $false, HelpMessage = 'Enter the Sentinel ResourceGroup')]
    [string] $ResourceGroup,
    [parameter(Position = 0, Mandatory = $false, HelpMessage = 'Enter the Sentinel WorkspaceName')]
    [string] $WorkspaceName,
    [parameter(Position = 1, Mandatory = $false, HelpMessage = 'Enter the Sentinel closure comment')]
    [string] $ClosureComment
)


$StartDate=[datetime]"03/01/2022 00:00"
$EndDate=[datetime]"03/31/2022 23:59"
$IncidentOwner = "user.name@tld.com"
$Classification = "Undetermined"
$ClosureComment ="Incidents older than the workspace retention of 90 days have their entities removed. Bulk closed using REST API"

$SentinelConnection = @{
    ResourceGroupName = $ResourceGroup
    WorkspaceName = $WorkspaceName
    }

$Incidents = Get-AzSentinelIncident @SentinelConnection `
    | Where-Object {($_.CreatedTimeUtc -ge $StartDate -and $_.CreatedTimeUtc -lt $EndDate) -and ($_.Status -ne "Closed")} `
    | Select-Object Name, Title, Severity

$Incidents | ForEach-Object `
    {
        $IncidnetId = $_.Name
        Update-AzSentinelIncident @SentinelConnection `
            -Id $_.Name `
            -Title $_.Title `
            -Severity $_.Severity `
            -Status Closed `
            -OwnerAssignedTo  $IncidentOwner `
            -Classification $Classification `
            -ClassificationComment $ClosureComment `
            -Confirm:$false
    }