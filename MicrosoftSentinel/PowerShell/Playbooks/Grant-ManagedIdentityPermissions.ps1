<#
.SYNOPSIS
    Grants Microsoft Graph API permissions and Entra ID directory roles to a managed identity.

.DESCRIPTION
    This script automates the assignment of Microsoft Graph API permissions and Entra ID directory roles 
    to a managed identity. It assigns User.ManageIdentities.All, SynchronizationData-User.Upload, and 
    AuditLog.Read.All Graph permissions, plus the User Administrator directory role.

.PARAMETER ManagedIdentityObjectId
    The Object ID of the managed identity to grant permissions to.
    Default: "LogticApp-Identity-ObjectId" (must be replaced with actual Object ID)

.PARAMETER GraphPermissions
    Array of Microsoft Graph permissions to assign.
    Default: @("User.ManageIdentities.All", "SynchronizationData-User.Upload", "AuditLog.Read.All")

.PARAMETER DirectoryRole
    The Entra ID directory role to assign.
    Default: "User Administrator"

.EXAMPLE
    .\Grant-ManagedIdentityPermissions.ps1
    Runs the script with default parameters (requires updating the Object ID first)

.EXAMPLE
    .\Grant-ManagedIdentityPermissions.ps1 -ManagedIdentityObjectId "12345678-1234-1234-1234-123456789012"
    Assigns permissions to the specified managed identity

.NOTES
    File Name      : Grant-ManagedIdentityPermissions.ps1
    Author         : noodlemctwoodle
    Prerequisite   : Microsoft Graph PowerShell module, Global Administrator or Privileged Role Administrator rights
    Created        : $(Get-Date -Format "yyyy-MM-dd")
    Version        : 1.0
    
    SECURITY WARNING: This script grants high-privilege permissions. Review the permissions being granted
    and ensure they align with the principle of least privilege for your use case.

.LINK
    https://docs.microsoft.com/en-us/graph/permissions-reference
    https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference
#>

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

# Set your managed identity's object ID
$miObjectId = "LogticApp-Identity-ObjectId"

# Microsoft Graph service principal ID
$graphId = "00000003-0000-0000-c000-000000000000"

# Get Microsoft Graph service principal
$graphSP = Get-MgServicePrincipal -Filter "appId eq '$graphId'"

# Define all permissions to assign
$permissionsToAssign = @(
    "User.ManageIdentities.All",
    "SynchronizationData-User.Upload",
    "AuditLog.Read.All"
)

# Get required app roles from Microsoft Graph
$roles = @{}
foreach ($permission in $permissionsToAssign) {
    $roles[$permission] = $graphSP.AppRoles | Where-Object { $_.Value -eq $permission }
    
    # Verify the permission exists
    if ($null -eq $roles[$permission]) {
        Write-Warning "Permission '$permission' not found in Microsoft Graph API"
    }
}

# Create parameter hashtable
$params = @{
    ServicePrincipalId = $miObjectId
    PrincipalId = $miObjectId
    ResourceId = $graphSP.Id
}

# Assign permissions
foreach ($role in $roles.Keys) {
    # Skip if permission was not found
    if ($null -eq $roles[$role]) {
        continue
    }
    
    # Check if the permission is already assigned
    $existingAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $miObjectId | 
        Where-Object { $_.AppRoleId -eq $roles[$role].Id -and $_.ResourceId -eq $graphSP.Id }
    
    if ($existingAssignment) {
        Write-Host "Permission $role is already assigned" -ForegroundColor Yellow
    }
    else {
        $roleParams = $params.Clone()
        $roleParams.AppRoleId = $roles[$role].Id
        
        try {
            New-MgServicePrincipalAppRoleAssignment @roleParams
            Write-Host "Assigned $role permission" -ForegroundColor Cyan
        }
        catch {
            Write-Host "Failed to assign $role permission: $_" -ForegroundColor Red
        }
    }
}

Write-Host "All Graph permissions assigned!" -ForegroundColor Green

# Entra ID role displayname 
$roleName = "User Administrator"

# Get all directory roles
$directoryRoles = Get-MgDirectoryRole -All

# Find the User Administrator role
$role = $directoryRoles | Where-Object { $_.DisplayName -eq $roleName }

# If the role isn't activated yet, we need to activate it
if (-not $role) {
    # Get all role templates
    $roleTemplates = Get-MgDirectoryRoleTemplate -All
    
    # Find the User Administrator template
    $roleTemplate = $roleTemplates | Where-Object { $_.DisplayName -eq $roleName }
    
    if ($roleTemplate) {
        # Activate the role from the template
        $params = @{
            RoleTemplateId = $roleTemplate.Id
        }
        $role = New-MgDirectoryRole -BodyParameter $params
        Write-Host "Activated the $roleName role" -ForegroundColor Cyan
    }
    else {
        Write-Error "Could not find the $roleName role template."
        exit 1
    }
}

# Check if the role is already assigned to the managed identity
$roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$miObjectId'" -All

$existingRoleAssignment = $roleAssignments | Where-Object { 
    $_.RoleDefinitionId -eq $role.RoleTemplateId -and 
    $_.DirectoryScopeId -eq "/"
}

if ($existingRoleAssignment) {
    Write-Host "The $roleName role is already assigned to the managed identity" -ForegroundColor Yellow
}
else {
    # Now assign the role to the managed identity
    try {
        # Create role assignment
        $params = @{
            DirectoryScopeId = "/"
            RoleDefinitionId = $role.RoleTemplateId
            PrincipalId = $miObjectId
        }
        
        New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $params
        Write-Host "Assigned $roleName role to the managed identity" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to assign $roleName role: $_" -ForegroundColor Red
    }
}