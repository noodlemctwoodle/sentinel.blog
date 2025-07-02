#Requires -Version 6
#Requires -Modules Az.SecurityInsights

<#
.EXAMPLE
.\Close-IncidentTitleUndetermined.ps1 -ResourceGroupName "<ResourceGroupName>" -WorkspaceName "<WorkspaceName>" -ClassificationComment "Closed By PowerShell"

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
    | ? Title -eq "Email messages containing malicious URL removed after delivery​" `
    | ? Status -ne "Closed"  `
    | ForEach-Object {update-AzSentinelIncident @SentinelConnection `
        -IncidentID $_.Name -Status Closed -Classification "Undetermined" -ClassificationComment "$ClassificationComment" -Confirm:$false}

