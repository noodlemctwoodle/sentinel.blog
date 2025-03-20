# Microsoft Graph API Permissions Script for Sentinel Watchlists

This PowerShell script is designed to configure the necessary Microsoft Graph API permissions for a Logic App's System-Assigned Managed Identity. These permissions allow the Logic App to read group memberships from Entra ID (formerly Azure AD) for synchronization with Microsoft Sentinel watchlists.

## Purpose

The script grants the following permissions to your Logic App's Managed Identity:

- **Group.Read.All**: Allows reading group information and membership
- **Directory.Read.All**: Allows reading directory data, which is needed for some group operations

These permissions enable secure, passwordless access to Microsoft Graph API from your Logic App.

## Prerequisites

- PowerShell 7.0+
- Microsoft.Graph PowerShell modules installed
- Global Administrator or Privileged Role Administrator permissions in your Entra ID tenant
- A Logic App with System-Assigned Managed Identity enabled

## Usage

1. Edit the script and replace `YOUR-MANAGED-IDENTITY-OBJECT-ID` with your Logic App's Managed Identity Object ID
2. Run the script in an elevated PowerShell session
3. Authenticate with an account that has admin permissions when prompted

```powershell
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
```

## Finding Your Managed Identity Object ID

You can find your Logic App's Managed Identity Object ID in the Azure Portal:

1. Navigate to your Logic App
2. Go to Settings > Identity
3. Switch to the System assigned tab
4. The Object (principal) ID is displayed after enabling the identity

## Related Blog Post

For a complete guide on setting up automated Sentinel watchlists from Entra ID groups, please read our detailed blog post:

[Automating Security: Creating Microsoft Sentinel Watchlists from Entra ID Group Membership](https://sentinel.blog/automating-security-creating-microsoft-sentinel-watchlists-from-entra-id-group-membership/)

The blog post provides comprehensive step-by-step instructions for:

- Creating and configuring the Logic App
- Setting up all necessary permissions
- Building the workflow to sync group members to watchlists
- Using the watchlists in Sentinel analytics rules

## Troubleshooting

If you encounter permission errors:

- Ensure you're running the script with sufficient privileges
- Verify that the Managed Identity Object ID is correct
- Check that the System-Assigned Managed Identity is enabled on your Logic App

## License

This script is provided under the MIT License. Feel free to modify and use it as needed for your environment.