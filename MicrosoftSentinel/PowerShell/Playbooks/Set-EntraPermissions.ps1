<#

#Requires -Version 7
#Requires -Modules Microsoft.Graph

.DESCRIPTION
    The script is intended to be run as part of the deployment of the Microsoft Sentinel XDR Playbooks and requires the Microsoft Graph PowerShell module and a Global Administrator account.    
    The script will assign the required permissions to the Managed Identity used by the Microsoft Sentinel XDR Logic Apps.
    The permissions are required for the Microsoft Sentinel Request Logic Apps to be able to perform the following actions:
        - Restrict and Unrestrict App Execution
        - Isolate and Unisolate Machines
        - Block and Enable EntraId Users
    
.EXAMPLE
    .\Assign-Permissions.ps1
.NOTES
    Version:          1.0
    Author:           noodlemctwoodle
    Creation Date:    04/01/2023
.LINK
    https://learn.microsoft.com/en-us/powershell/microsoftgraph/get-started?view=graph-powershell-1.0
#>

# Define the tenant ID for Microsoft Graph connection
$tenantId = "<Your Tenant Id>"

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module -Name Microsoft.Graph -scope CurrentUser -Force
}

Connect-MgGraph -TenantId $tenantId

function Set-RestrictMDEAppExecution {
    param($MIGuid)
    $MI = Get-MgServicePrincipal -ServicePrincipalId $MIGuid
    $MDEAppId = "fc780465-2017-40d4-a0c5-307022471b92"
    $PermissionName = "Machine.RestrictExecution"
    $MDEServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$MDEAppId'"
    $AppRole = $MDEServicePrincipal.AppRoles | Where-Object { $_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application" }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MI.Id -PrincipalId $MI.Id -ResourceId $MDEServicePrincipal.Id -AppRoleId $AppRole.Id
}

function Set-UnrestrictMDEAppExecution {
    param($MIGuid)
    Set-RestrictMDEAppExecution -MIGuid $MIGuid
}

function Set-IsolateMDEMachine {
    param($MIGuid)
    $MI = Get-MgServicePrincipal -ServicePrincipalId $MIGuid
    $MDEAppId = "fc780465-2017-40d4-a0c5-307022471b92"
    $PermissionName = "Machine.Isolate"

    $MDEServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$MDEAppId'"
    $AppRole = $MDEServicePrincipal.AppRoles | Where-Object { $_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application" }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MI.Id -PrincipalId $MI.Id -ResourceId $MDEServicePrincipal.Id -AppRoleId $AppRole.Id
}

function Set-UnIsolateMDEMachine {
    param($MIGuid)
    Set-IsolateMDEMachine -MIGuid $MIGuid
}

function Set-BlockEntraIdUser {
    param($MIGuid)
    $MI = Get-MgServicePrincipal -ServicePrincipalId $MIGuid
    $GraphAppId = "00000003-0000-0000-c000-000000000000"
    $PermissionNames = @("Directory.ReadWrite.All", "User.ReadWrite.All", "User.EnableDisableAccount.All")

    $GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
    foreach ($PermissionName in $PermissionNames) {
        $AppRole = $GraphServicePrincipal.AppRoles | Where-Object { $_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application" }
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MI.Id -PrincipalId $MI.Id -ResourceId $GraphServicePrincipal.Id -AppRoleId $AppRole.Id
    }
}

function Set-EnableEntraIdUser {
    param($MIGuid)
    Set-BlockEntraIdUser -MIGuid $MIGuid
}

function Set-AddXDRThreatIntelligence {
    param($MIGuid)
    $MI = Get-MgServicePrincipal -ServicePrincipalId $MIGuid
    $MDEAppId = "fc780465-2017-40d4-a0c5-307022471b92"
    $PermissionName = "Ti.ReadWrite.All"
    $MDEServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$MDEAppId'"
    $AppRole = $MDEServicePrincipal.AppRoles | Where-Object { $_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application" }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MI.Id -PrincipalId $MI.Id -ResourceId $MDEServicePrincipal.Id -AppRoleId $AppRole.Id
}

function Set-XDRScanMachine {
    param($MIGuid)
    $MI = Get-MgServicePrincipal -ServicePrincipalId $MIGuid
    $MDEAppId = "fc780465-2017-40d4-a0c5-307022471b92"
    $PermissionNames = @("Machine.Scan", "Machine.Read.All", "Machine.ReadWrite.All")
    $MDEServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$MDEAppId'"
    
    foreach ($PermissionName in $PermissionNames) {
        $AppRole = $MDEServicePrincipal.AppRoles | Where-Object { $_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application" }
        if ($AppRole) {
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MI.Id -PrincipalId $MI.Id -ResourceId $MDEServicePrincipal.Id -AppRoleId $AppRole.Id
        } else {
            Write-Warning "AppRole for permission '$PermissionName' not found."
        }
    }
}


# Replace "<Your Managed Identity ObjectId>" with the actual ID
Set-RestrictMDEAppExecution -MIGuid "<Your Managed Identity ObjectId>"
Set-UnrestrictMDEAppExecution -MIGuid "<Your Managed Identity ObjectId>"
Set-IsolateMDEMachine -MIGuid "<Your Managed Identity ObjectId>"
Set-UnIsolateMDEMachine -MIGuid "<Your Managed Identity ObjectId>"
Set-BlockEntraIdUser -MIGuid "<Your Managed Identity ObjectId>"
Set-EnableEntraIdUser -MIGuid "<Your Managed Identity ObjectId>"
