# Azure Log Analytics Table Retention Management Script

A modern PowerShell script for managing retention policies on Azure Log Analytics workspace tables with an interactive console-based GUI experience.

## Overview

This script provides a streamlined approach to managing table retention settings across Log Analytics workspaces. It utilises `Out-ConsoleGridView` for all user interactions, ensuring a consistent and professional experience across Windows, Linux, and macOS platforms.

## Key Features

- 🖥️ **Interactive Console GUI** - Modern grid-based selection interfaces
- 🔍 **Real-time Table Discovery** - Only shows tables that actually contain data
- 📊 **Plan-based Filtering** - Separate handling for Analytics and Basic plan tables
- ✅ **Multi-select Management** - Select multiple tables for batch operations
- 📝 **Comprehensive Logging** - Detailed audit trail with timestamp logging
- 🔒 **Validation & Safety** - Multiple confirmation steps and error handling
- 🌐 **Cross-platform Compatible** - Works on Windows, Linux, and macOS

## Prerequisites

### PowerShell Requirements

- **PowerShell 7.4.x or later**

### Required Modules

The script will automatically install missing modules:

- `Az.Accounts` - Azure authentication
- `Az.OperationalInsights` - Log Analytics management
- `Microsoft.PowerShell.ConsoleGuiTools` - Modern console interfaces

### Azure Permissions

Your account must have the following permissions on target Log Analytics workspaces:

- **Log Analytics Contributor** (or higher)
- `Microsoft.OperationalInsights/workspaces/tables/write`
- `Microsoft.OperationalInsights/workspaces/query/read`

## Installation

1. **Download the script** to your preferred location
2. **Set execution policy** (if required):
3. 
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
4. **Run the script** with required parameters

## Usage

### Basic Syntax

```powershell
.\Set-LATableRetention.ps1 -TenantID "<your-tenant-id>" -RetentionDays <days> [-TablePlan <plan>]
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `TenantID` | String | Yes | EntraID Tenant ID for Azure authentication |
| `RetentionDays` | Integer | Yes | Number of days for retention (4-4383) |
| `TablePlan` | String | No | Target plan type: `Analytics` or `Basic` (default: Analytics) |

### Retention Limits by Plan Type

| Plan Type | Minimum Days | Maximum Days | Description |
|-----------|--------------|--------------|-------------|
| **Analytics** | 4 | 4383 (~12 years) | Full-featured analytics tables |
| **Basic** | 4 | 90 | Cost-optimised basic ingestion |

## Examples

### Example 1: Set Analytics Tables to 1 Year

```powershell
.\Set-LATableRetention.ps1 -TenantID "12345678-1234-1234-1234-123456789012" -RetentionDays 365
```

- Filters to Analytics plan tables by default
- Sets retention to 365 days (1 year)
- Interactive selection for workspace and tables

### Example 2: Set Basic Tables to 30 Days

```powershell
.\Set-LATableRetention.ps1 -TenantID "12345678-1234-1234-1234-123456789012" -RetentionDays 30 -TablePlan "Basic"
```

- Filters to Basic plan tables only
- Sets retention to 30 days
- Interactive selection process

### Example 3: Long-term Analytics Retention

```powershell
.\Set-LATableRetention.ps1 -TenantID "12345678-1234-1234-1234-123456789012" -RetentionDays 2555 -TablePlan "Analytics"
```

- Sets retention to approximately 7 years
- Useful for compliance or audit requirements

## Workflow

The script follows a structured workflow with multiple confirmation points:

### 1. Authentication & Setup

- Validates and installs required PowerShell modules
- Authenticates to Azure using the provided Tenant ID
- May display native Azure subscription selection if multiple subscriptions exist

### 2. Workspace Selection

- Discovers available Log Analytics workspaces
- Presents interactive grid for workspace selection
- Shows workspace name, resource group, and location

### 3. Table Discovery

- Queries workspace Usage data to identify tables with actual data
- Cross-references with Azure Management API for table configuration
- Filters out phantom tables and system tables without retention settings

### 4. Table Selection

- Filters tables based on the specified `TablePlan` parameter
- Presents interactive grid showing table name, plan type, and current retention
- Supports multi-select for batch operations

### 5. Confirmation & Updates

- Shows before/after retention comparison
- Final confirmation with option to deselect specific tables
- Executes batch updates via Azure Management API
- Provides detailed success/failure reporting

## Table Discovery Logic

The script employs intelligent table discovery to ensure only relevant tables are shown:

### Inclusion Criteria

- ✅ Tables with billable data in the last 30 days
- ✅ Tables with proper retention configuration
- ✅ Tables in 'Succeeded' provisioning state
- ✅ Tables matching the specified plan type

### Exclusion Criteria

- ❌ System tables without retention settings
- ❌ Phantom tables (exist in API but no data)
- ❌ Tables in 'Deleting' or 'Failed' states
- ❌ Tables without essential properties

## Logging & Audit Trail

### Log File Location

Logs are automatically saved to: `LARetention_YYYYMMDD_HHMMSS.log`

### Log Content

- Timestamp and severity level for each entry
- Detailed operation tracking
- Error messages and stack traces
- User selections and confirmations
- API call details and responses

### Severity Levels

- **Information** - Normal operations (green)
- **Warning** - Non-critical issues (yellow)  
- **Error** - Critical failures (red)

## Error Handling

The script includes comprehensive error handling:

### Common Issues & Solutions

| Error | Cause | Solution |
|-------|--------|----------|
| No workspaces found | Insufficient permissions | Verify RBAC assignments |
| No tables discovered | Empty workspace or permissions | Check data ingestion and permissions |
| API authentication failed | Token expired or invalid | Re-run authentication |
| Retention update failed | Invalid retention value | Check plan-specific limits |

### Troubleshooting Steps

1. **Check the log file** for detailed error information
2. **Verify Azure permissions** on target workspaces
3. **Confirm table plan types** match your expectations
4. **Validate retention day values** against plan limits
5. **Ensure PowerShell modules** are up to date

## Security Considerations

### Authentication

- Uses Azure PowerShell authentication flow
- Supports multi-factor authentication
- Token-based API access with automatic refresh

### Permissions

- Follows principle of least privilege
- Only requires necessary Log Analytics permissions
- No persistent credential storage

### Audit Trail

- Complete operation logging
- User action tracking
- API call documentation

## Best Practices

### Before Running

- ✅ **Test in non-production** environments first
- ✅ **Review current retention settings** to avoid data loss
- ✅ **Understand retention implications** for your use case
- ✅ **Verify backup strategies** if reducing retention

### During Operation

- ✅ **Review table selections** carefully before confirming
- ✅ **Check confirmation screen** for accuracy
- ✅ **Monitor log output** for any warnings or errors
- ✅ **Keep log files** for audit purposes

### After Completion

- ✅ **Verify changes** in Azure portal
- ✅ **Document changes** for compliance
- ✅ **Monitor data retention** effects over time
- ✅ **Review costs** if retention was increased

## Compatibility

### Operating Systems

- ✅ Windows 10/11 with PowerShell 7.x
- ✅ Windows Server 2016/2019/2022 with PowerShell 7.x
- ✅ macOS with PowerShell 7.x
- ✅ Linux distributions with PowerShell 7.x

### Azure Environments

- ✅ Azure Commercial Cloud
- ✅ Azure Government Cloud
- ✅ Azure China Cloud (21Vianet)

## Version History

### Version 2.0 (Current)

- Modern interactive console GUI using Out-ConsoleGridView
- Enhanced table discovery with Usage data validation
- Improved error handling and logging
- Cross-platform compatibility
- British English localisation

### Key Improvements from v1.x

- Eliminated phantom table display issues
- Added real-time table existence validation
- Enhanced user experience with consistent GUI
- Improved performance and reliability
- Better error reporting and troubleshooting

## Support & Contributing

### Getting Help

- Review the log files for detailed error information
- Check Azure portal for permission and workspace status
- Verify PowerShell module versions and compatibility

### Reporting Issues

When reporting issues, please include:

- PowerShell version (`$PSVersionTable`)
- Operating system details
- Complete error messages
- Relevant log file excerpts
- Steps to reproduce the issue

## License

This script is provided as-is for educational and operational purposes. Please ensure compliance with your organisation's policies and Azure terms of service.

