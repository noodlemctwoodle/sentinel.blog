#Requires -Version 6
#Requires -Modules Az.SecurityInsights

<#
.EXAMPLE
.\Close-IncidentsUndetermined.ps1 -ResourceGroupName "secops-eus-rg-001" -WorkspaceName "SECOPS-EUS-LA-001" -ClassificationComment "Closed By PowerShell"
.NOTES
  Version:          0.2
  Author:           noodlemctwoodle
  Creation Date:    05/04/2023
.LINK
https://docs.microsoft.com/en-us/powershell/module/az.securityinsights/?view=azps-7.1.0#security-insights
#>

param (
    [Parameter(Position=0,mandatory=$true)]
    [string]$ResourceGroupName,
    [Parameter(Position=1,mandatory=$true)]
    [string]$WorkspaceName,
    [Parameter(Position=2,mandatory=$true)]
    [string[]]$ClassificationComment

    )

$SentinelConnection = @{
    ResourceGroupName = $ResourceGroupName
    WorkspaceName = $WorkspaceName
}

Get-AzSentinelIncident @SentinelConnection `
    | where Status -ne "closed" | where Name -eq  `
    | ForEach-Object {update-AzSentinelIncident @SentinelConnection `
        -IncidentID $_.Name -Status Closed -Classification "Undetermined" -ClassificationComment "$ClassificationComment" -Confirm:$false}