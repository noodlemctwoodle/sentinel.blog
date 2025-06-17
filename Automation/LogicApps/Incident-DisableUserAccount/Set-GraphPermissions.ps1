# Connect to Microsoft Graph
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

# Set your managed identity's object ID
$miObjectId = "LogticApp-Identity-ObjectId"

# Microsoft Graph service principal ID
$graphId = "ae166721-e002-49f5-8de5-7c682e782b7e"

# Get Microsoft Graph service principal
$graphSP = Get-MgServicePrincipal -Filter "appId eq '$graphId'"

# Define all permissions to assign
$permissionsToAssign = @(
    "Directory.ReadWrite.All", 
    "User.ReadWrite.All"
    "User.RevokeSessions.All"
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