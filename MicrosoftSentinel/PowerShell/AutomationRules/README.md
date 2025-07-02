# Microsoft Sentinel Automation Rule Management Script

This PowerShell script provides a comprehensive solution for managing Microsoft Sentinel automation rules in Microsoft Sentinel. It includes functionalities such as authenticating to Azure, retrieving, deploying, and exporting Microsoft Sentinel automation rules.

## Features

- **Azure Authentication**: Checks if the current PowerShell session is already authenticated to a specific Azure tenant and authenticates if not.
- **Retrieve Microsoft Sentinel Resources**: Allows the selection of Azure subscriptions, resource groups, and Log Analytics Workspaces through a graphical interface.
- **Get and Deploy Automation Rules**: Retrieves and deploys Microsoft Sentinel automation rules.
- **Export Automation Rules to JSON**: Provides an option to export retrieved automation rules to JSON files.

## Prerequisites

- [PowerShell 7](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.4)
- [Out-ConsoleGridView](https://devblogs.microsoft.com/powershell/introducing-consoleguitools-preview/)
- Microsoft Sentinel Contributor required to access and manage Microsoft Sentinel resources in Azure.

## Usage

1. **Starting the Script**:
   - Run the script in a PowerShell environment.
   - It automatically checks for Azure authentication.

2. **Selecting Resources**:
   - Follow the prompts to select the Azure subscription, resource group, and workspace.

3. **Managing Automation Rules**:
   - The script provides options to:
     - Retrieve existing automation rules.
     - Export these rules to JSON files.
     - Deploy or update automation rules.

4. **Exporting and Deploying Rules**:
   - Choose whether to export the rules to JSON.
   - Select rules for deployment, either individually, all at once, or cancel the operation.

## Functions

### `Write-Log`
Logs messages with a timestamp to a specified log file.

### `Get-AuthToken`
Retrieves an authentication token for Azure Sentinel REST API requests.

### `Get-MicrosoftSentinelResources`
Interactively selects Azure Subscription, Resource Group, and Microsoft Sentinel Workspace.

### `Get-MicrosoftSentinelAutomationRules`
Fetches automation rules from a specified Microsoft Sentinel workspace.

### `Set-MicrosoftSentinelAutomationRules`
Deploys a previously selected automation rule to a specified Microsoft Sentinel workspace.

### `Export-AutomationRulesToJson`
Exports a collection of automation rules to JSON files.

## Script Configuration

- **Tenant ID**: Set the `$tenantId` variable with your Azure tenant ID.
- **Log File Path**: Set the log file path in the `Write-Log` function.
- **JSON File Export Path**: Set the `$jsonFilePath` variable for exporting rules to JSON.

## Notes

- The script includes error logging for troubleshooting.
- Uses a graphical interface for easier selection of resources.