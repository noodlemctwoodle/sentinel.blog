# Connect to Microsoft Graph
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All"

# Set your managed identity's object ID
$miObjectId = "160af8cc-77b7-4d36-b225-14c6772c3341"

# Microsoft Graph service principal ID
$graphId = "00000003-0000-0000-c000-000000000000"

# Get Microsoft Graph service principal
$graphSP = Get-MgServicePrincipal -Filter "appId eq '$graphId'"

# Get required app roles from Microsoft Graph
$roles = @{
    "Group.Read.All" = $graphSP.AppRoles | 
            Where-Object { $_.Value -eq "Group.Read.All" }
    "Directory.Read.All" = $graphSP.AppRoles | 
            Where-Object { $_.Value -eq "Directory.Read.All" }
}
# Create parameter hashtable
$params = @{
    ServicePrincipalId = $miObjectId
    PrincipalId = $miObjectId
    ResourceId = $graphSP.Id
}

# Assign permissions
foreach ($role in $roles.Keys) {
    $roleParams = $params.Clone()
    $roleParams.AppRoleId = $roles[$role].Id
    
    New-MgServicePrincipalAppRoleAssignment @roleParams
    Write-Host "Assigned $role permission" -ForegroundColor Cyan
}

Write-Host "All Graph permissions assigned!" -ForegroundColor Green