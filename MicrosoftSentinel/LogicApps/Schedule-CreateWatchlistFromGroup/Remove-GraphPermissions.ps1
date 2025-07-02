# Connect to Microsoft Graph
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All"

# Set your managed identity's object ID
$miObjectId = "LogticApp-Identity-ObjectId"

# Microsoft Graph service principal ID
$graphId = "00000003-0000-0000-c000-000000000000"

# Get current app role assignments for the managed identity
$currentAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $miObjectId

# Define the permissions to remove
$permissionsToRemove = @("Group.Read.All", "Directory.Read.All")

# Remove the specified permissions
foreach ($assignment in $currentAssignments) {
    # Get the app role details from the resource service principal
    $resourceSP = Get-MgServicePrincipal -ServicePrincipalId $assignment.ResourceId
    $appRole = $resourceSP.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
    
    # Check if this assignment matches one of our permissions to remove
    if ($appRole.Value -in $permissionsToRemove) {
        Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $miObjectId -AppRoleAssignmentId $assignment.Id
        Write-Host "Removed $($appRole.Value) permission" -ForegroundColor Yellow
    }
}

Write-Host "All specified Graph permissions removed!" -ForegroundColor Green