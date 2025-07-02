#Requires -Version 3
#Requires -Modules AzureAD

<#
.SYNOPSIS
Add Microsoft API Permissions (MicrosoftDefender & MicrosoftGraph) to User Assigned Managed Identity.
.DESCRIPTION
Add Microsoft API Permissions (MicrosoftDefender & MicrosoftGraph) to a User Assigned Managed Identity, Permissions can be added individually or as an array shown in the example.
Example MsApiTypes:
 - MicrosoftDefender
 - MicrosoftGraph
Example Permissions:
 - "Directory.Read.All"
 - "Group.Read.All"
 - "GroupMember.Read.All"
 - "Group.ReadWrite.All"
 - "GroupMember.ReadWrite.All"
Permissions can be discovered in Microsoft Graph Explorer https://developer.microsoft.com/en-us/graph/graph-explorer or on the Microsoft Reference Docs
.EXAMPLE
.\Assign-MsGraphPermissions.ps1 -MsApiType "MicrosoftDefender" -ManagedIdentity "DefenderATP-MI" -MsApiPermissions "AdvancedQuery.Read.All"
.\Assign-MsGraphPermissions.ps1 -MsApiType "MicrosoftGraph" -ManagedIdentity "362bc38e-01bf-4638-a884-93dfe0932689" -MsApiPermissions "User.ReadWriteAll", "Directory.Read.All"
.OUTPUTS
Adds Graph API Permissions for managed Identity for use with Azure AD HTTP Get Authentication
.NOTES
  Version:          0.3
  Author:           noodlemctwoodle
  Creation Date:    23/08/2022
.LINK
https://docs.microsoft.com/en-US/graph/api/overview?view=graph-rest-1.0
https://docs.microsoft.com/en-us/powershell/module/azuread/get-azureadserviceprincipal?view=azureadps-2.0
https://docs.microsoft.com/en-us/powershell/module/azuread/new-azureadserviceapproleassignment?view=azureadps-2.0
#>

param (
    [Parameter(Position = 0, mandatory = $true)]
    [string]$MsApiType,
    [Parameter(Position = 1, mandatory = $true)]
    [string]$ManagedIdentity,
    [Parameter(Position = 2, mandatory = $true)]
    [string[]]$MsApiPermissions

)

Try {
    Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue
}
Catch {
    Write-Host "No connection to Azure AD detected, connecting"; Connect-AzureAD
}

Function AssignPermissions ($MsApiType) {
    if ($MsApiType -eq "MicrosoftDefender") {
        $msDefenderAppId = "fc780465-2017-40d4-a0c5-307022471b92"
        foreach ($Permission in $MsApiPermissions) {
            $UserAssignedIdentity = (Get-AzureADServicePrincipal -Filter "displayName eq '$ManagedIdentity'")
            $GraphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$msDefenderAppId'"
            $ApplicationRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq $Permission -and $_.AllowedMemberTypes -contains "Application" }
            New-AzureAdServiceAppRoleAssignment -ObjectId $UserAssignedIdentity.ObjectId -PrincipalId $UserAssignedIdentity.ObjectId -ResourceId $GraphServicePrincipal.ObjectId -Id $ApplicationRole.Id
        }
    }
    elseif ($MsApiType -eq "MicrosoftGraph") {
        $msGraphAppId = "00000003-0000-0000-c000-000000000000"
        foreach ($Permission in $MsApiPermissions) {
            $UserAssignedIdentity = (Get-AzureADServicePrincipal -Filter "displayName eq '$ManagedIdentity'")
            $GraphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$msGraphAppId'"
            $ApplicationRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq $Permission -and $_.AllowedMemberTypes -contains "Application" }
            New-AzureAdServiceAppRoleAssignment -ObjectId $UserAssignedIdentity.ObjectId -PrincipalId $UserAssignedIdentity.ObjectId -ResourceId $GraphServicePrincipal.ObjectId -Id $ApplicationRole.Id
        }
    }
    else { exit }
}

AssignPermissions $MsApiType