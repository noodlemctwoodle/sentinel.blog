# Connect to Microsoft Graph with admin permissions
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All"

# Set your managed identity's object ID
$miObjectId = "YOUR-MANAGED-IDENTITY-OBJECT-ID"

# Microsoft Graph service principal ID (constant)
$graphId = "00000003-0000-0000-c000-000000000000"

# Get Microsoft Graph service principal
$graphSP = Get-MgServicePrincipal -Filter "appId eq '$graphId'"

# Get required app roles from Microsoft Graph
$groupRole = $graphSP.AppRoles | Where-Object { 
    $_.Value -eq "Group.Read.All" 
}
$dirRole = $graphSP.AppRoles | Where-Object { 
    $_.Value -eq "Directory.Read.All" 
}

# Assign Group.Read.All permission
New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $miObjectId `
    -PrincipalId $miObjectId `
    -ResourceId $graphSP.Id `
    -AppRoleId $groupRole.Id

# Assign Directory.Read.All permission
New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $miObjectId `
    -PrincipalId $miObjectId `
    -ResourceId $graphSP.Id `
    -AppRoleId $dirRole.Id

Write-Host "Graph permissions assigned!" -ForegroundColor Green