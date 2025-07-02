# Microsoft Sentinel Detections and Hunting Queries Guide

A comprehensive guide for creating, managing, and deploying custom detection rules and hunting queries in Microsoft Sentinel.

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Repository Setup](#-repository-setup)
- [Detection Rules](#-detection-rules)
- [Hunting Queries](#-hunting-queries)
- [Deployment](#-deployment)
- [Playbook Management](#-playbook-management)
- [Maintenance](#-maintenance)
- [Reference](#-reference)

## 🚀 Quick Start

### Prerequisites

- Azure DevOps account with repository access
- Microsoft Sentinel workspace
- PowerShell 7.x with required modules
- Appropriate Azure permissions

### Essential Tools

```powershell
# Install required PowerShell modules
Install-Module -Name PowerShell-Yaml -Scope CurrentUser -Force
Install-Module -Name SentinelARConverter -Scope CurrentUser -Force
Install-Module -Name Az.Resources -Scope CurrentUser
Install-Module -Name Az.LogicApp -Scope CurrentUser
```

## 🏗️ Repository Setup

### 1. Create Azure DevOps Connection

1. Navigate to **Microsoft Sentinel** → **Content management** → **Repositories**
2. Select **Add new** and configure:
   - **Name**: Meaningful connection name
   - **Source Control**: Azure DevOps
   - **Authorization**: Automatic using Azure credentials
3. Select your Organization, Project, Repository, Branch
4. Choose **all content types** for deployment
5. Click **Create**

### 2. Initial Repository Structure

After connection, your repository will contain:

```
.sentinel/
├── azure-sentinel-deploy-[Subscription-Id].ps1
├── sentinel-deploy-[Subscription-Id].yml
└── tracking_table_[Subscription-Id].csv
README.md
```

### 3. Configure Azure DevOps Pipeline

Update `.sentinel/sentinel-deploy-[Subscription-Id].yml`:

```yaml
steps:
- pwsh: |
    Install-Module -Name PowerShell-Yaml -Scope CurrentUser -Force
    Install-Module -Name SentinelARConverter -Scope CurrentUser -Force
  displayName: 'Install PowerShell Modules'

- pwsh: |
    $publishPath = "$(Build.SourcesDirectory)/Detections"
    Get-ChildItem -Path $publishPath -Recurse -Include *.yaml |
      ForEach-Object {
        Write-Host "Converting $($_.Name)"
        Convert-SentinelARYamlToArm -Filename $_.FullName -UseOriginalFilename
        Write-Host "Successfully converted $($_.Name)"
        Remove-Item $_.FullName -Force
      }
  displayName: 'Convert YAML to ARM'

- task: AzurePowerShell@5
  displayName: 'Deploy Sentinel Content'
```

## 🔍 Detection Rules

### YAML Template Structure

All detection rules use YAML format with the following structure. **Note: Major updates in 2024-2025 require attention to mandatory fields and deprecated elements.**

```yaml
id: "a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8"  # Required: Unique GUID (generate using New-Guid or online tools)
name: "Detection Rule Name"                    # Required: <50 chars, sentence case, descriptive
description: |                                # Required: Max 5 sentences, start with "Identifies" or "This query searches for"
  'Brief description of what this rule detects and why it matters.'
severity: "High"                              # Required: Informational|Low|Medium|High (based on business impact)
requiredDataConnectors:                       # Required: List connectors needed, use [] if none
  - connectorId: "AzureActiveDirectory"       # Must match official connector IDs
    dataTypes:                               # List all required data types
      - "SigninLogs"
queryFrequency: "PT5M"                        # Required: How often to run (PT5M=5min, PT1H=1hour, P1D=1day)
queryPeriod: "P1D"                           # Required: Time window to analyze (must be >= queryFrequency)
triggerOperator: "gt"                        # Required: Comparison operator (gt=greater than, lt=less than, eq=equals)
triggerThreshold: 5                          # Required: Threshold value (0-10000)
status: "Available"                          # Optional: Available|Disabled (controls rule state)
tactics:                                     # Required: MITRE ATT&CK v16 tactics (no spaces in names)
  - "InitialAccess"                          # Must be valid MITRE tactics
  - "LateralMovement"
techniques:                                  # Required: MITRE ATT&CK technique IDs
  - "T1078"                                  # Valid Accounts
  - "T1078.001"                             # Sub-techniques supported (Default Accounts)
tags:                                        # Required for custom rules (helps categorize)
  - "SecurityOps"
query: |                                     # Required: KQL query (10,000 char limit)
  SigninLogs                                 # Must return columns referenced in entityMappings
  | where TimeGenerated >= ago(1d)          # Include time filters for performance
  | where ResultType != 0                   # Filter failed logins
  | summarize FailedAttempts = count() by UserPrincipalName, IPAddress
  | where FailedAttempts > 5                # Apply thresholds
entityMappings:                              # MANDATORY: Map query results to entities (up to 10 mappings)
  - entityType: "Account"                    # Must be valid entity type
    fieldMappings:                           # Up to 3 identifiers per entity
      - identifier: "FullName"               # Must match entity type identifiers
        columnName: "UserPrincipalName"      # Must match query output column
      - identifier: "Name"
        columnName: "AccountName"
  - entityType: "IP"
    fieldMappings:
      - identifier: "Address"
        columnName: "IPAddress"
incidentConfiguration:                       # Optional: Controls incident creation and grouping
  createIncident: true                       # Whether to create incidents from alerts
  groupingConfiguration:
    enabled: true                            # Enable alert grouping
    reopenClosedIncident: false              # Reopen closed incidents for related alerts
    lookbackDuration: "PT5H"                # How far back to look for grouping
    matchingMethod: "AllEntities"            # AllEntities|AnyAlert|Selected
    groupByEntities: ["Account", "IP"]       # Group by specific entity types
    groupByAlertDetails: []                  # Group by alert properties
    groupByCustomDetails: []                 # Group by custom detail fields
eventGroupingSettings:                       # Optional: Controls alert generation
  aggregationKind: "SingleAlert"             # SingleAlert=one per query, AlertPerResult=one per row
suppressionDuration: "PT5H"                 # Optional: Prevent duplicate alerts (ISO 8601 format)
suppressionEnabled: false                   # Optional: Enable/disable suppression
alertDetailsOverride:                        # Optional: Dynamic alert customization
  alertDisplayNameFormat: "Failed login from {{IPAddress}} for {{UserPrincipalName}}"  # Max 3 params, 256 chars
  alertDescriptionFormat: "{{FailedAttempts}} failed attempts detected"                # Max 3 params, 5000 chars
  alertSeverityColumnName: "DynamicSeverity" # Column name for dynamic severity
  alertTacticsColumnName: "DynamicTactics"   # Column name for dynamic tactics
customDetails:                               # Optional: Surface event data in alerts (up to 20 pairs)
  FailedAttemptCount: "FailedAttempts"       # Key: column name mapping
  SourceLocation: "Location"                 # Improves analyst efficiency
  TimeWindow: "TimeWindowAnalyzed"
version: "1.0.0"                            # Required: Template version (increment for updates)
kind: "Scheduled"                           # Required: Rule type determines execution method
```

#### Field Descriptions

| Field | Required | Description | Values/Format |
|-------|----------|-------------|---------------|
| `id` | Yes | Unique identifier for the rule | GUID format (generate with New-Guid) |
| `name` | Yes | Short descriptive name | <50 characters, sentence case |
| `description` | Yes | Detailed explanation of the rule | Max 5 sentences, start with "Identifies" |
| `severity` | Yes | Impact level of true positives | Informational, Low, Medium, High |
| `requiredDataConnectors` | Yes | Data sources needed | List of connector objects or [] |
| `queryFrequency` | Yes | How often to run the query | ISO 8601 duration (PT5M, PT1H, P1D) |
| `queryPeriod` | Yes | Time window to analyze | ISO 8601 duration, >= queryFrequency |
| `triggerOperator` | Yes | Comparison operator for threshold | gt, lt, eq |
| `triggerThreshold` | Yes | Number that triggers alert | Integer 0-10000 |
| `status` | No | Rule operational state | Available, Disabled |
| `tactics` | Yes | MITRE ATT&CK tactics | Array of valid tactic names (no spaces) |
| `techniques` | Yes | MITRE ATT&CK techniques | Array of technique IDs (T1078, T1078.001) |
| `tags` | Yes* | Rule categorization | Array of strings (*required for custom rules) |
| `query` | Yes | KQL detection logic | Valid KQL, max 10,000 characters |
| `entityMappings` | Yes | Entity extraction configuration | 1-10 mappings, 500 entities total |
| `incidentConfiguration` | No | Incident creation settings | Object with grouping configuration |
| `eventGroupingSettings` | No | Alert generation control | SingleAlert or AlertPerResult |
| `suppressionDuration` | No | Duplicate prevention window | ISO 8601 duration |
| `suppressionEnabled` | No | Enable suppression | true or false |
| `alertDetailsOverride` | No | Dynamic alert properties | Object with format strings |
| `customDetails` | No | Additional alert context | Key-value pairs, max 20 |
| `version` | Yes | Template version | Semantic versioning (1.0.0) |
| `kind` | Yes | Rule execution type | Scheduled, NRT, Fusion, etc. |

### Essential Guidelines

#### Naming Conventions

- **Use sentence case**: "Failed login attempts from suspicious IP"
- **Keep under 50 characters** when possible
- **Be specific about entities and data types**
- **Avoid**: "Suspicious", "IP" (use "IPAddress"), "Execute" (use "Run")

#### Critical 2024-2025 Updates

⚠️ **BREAKING CHANGES - Action Required:**

1. **Threat Intelligence Migration (Deadline: July 31, 2025)**
   - Legacy `ThreatIntelligenceIndicator` table will be retired
   - Update all rules to use new `ThreatIntelIndicators` and `ThreatIntelObjects` tables
   - Migrate to STIX 2.1 schema format

2. **Entity Mappings Now Mandatory**
   - All templates MUST include `entityMappings` section
   - Legacy custom entity fields (`AccountCustomEntity`, `HostCustomEntity`) deprecated
   - Up to 10 entity mappings per rule, 500 entities total

3. **Time Format Standardization**
   - All time values must use ISO 8601 format: `PT5M`, `PT1H`, `P1D`
   - Legacy formats like `5m`, `1h`, `1d` are deprecated

4. **MITRE ATT&CK Framework v16**
   - Updated to latest framework version
   - `relevantTechniques` field renamed to `techniques`
   - Sub-techniques now supported (e.g., `T1078.001`)

#### Time Format Requirements

| Field | Format | Example | Legacy (Deprecated) |
|-------|--------|---------|-------------------|
| queryFrequency | ISO 8601 | `PT5M`, `PT1H` | `5m`, `1h` |
| queryPeriod | ISO 8601 | `PT1H`, `P1D` | `1h`, `1d` |
| suppressionDuration | ISO 8601 | `PT5H` | `5h` |
| lookbackDuration | ISO 8601 | `PT5H` | `5h` |

#### Query Best Practices

```kql
// ✅ Good: Use descriptive variable names
let FailedLoginThreshold = 5;
let TimeWindow = 1d;
let SuspiciousResultTypes = dynamic([50126, 50053, 50074]);

// ✅ Good: Include comments for clarity
// Exclude known service accounts and expected failures
| where UserPrincipalName !endswith "svc.example.com"
| where ResultType !in (SuspiciousResultTypes)

// ✅ Good: Return relevant fields for investigation
| project TimeGenerated, UserPrincipalName, IPAddress, 
          Location, ResultType, ResultDescription

// ⚠️ Critical: Threat Intelligence Migration Required
// OLD (Will stop working July 31, 2025):
ThreatIntelligenceIndicator
| where Active == true
| where IndicatorType == "DomainName"

// NEW (Required format):
ThreatIntelIndicators
| where IsDeleted == false
| where Data.pattern contains "domain-name"

// ❌ Avoid: Hardcoded values without explanation
| where count_ > 5  // What does 5 represent?

// ❌ Avoid: Missing time bounds for complex queries
// Always include time filters for historical comparisons

// ❌ Avoid: Legacy time formats (deprecated)
| where TimeGenerated > ago(1h)  // Use PT1H in queryPeriod instead
```

#### Entity Mapping Requirements (MANDATORY)

**Entity mappings are now mandatory for all templates.** The system supports up to 10 entity mappings per rule with a total of 500 entities across all mappings.

**Supported entity types (2024-2025 updates):**

| Entity Type | Key Identifiers | Features |
|-------------|----------------|----------|
| Account | FullName, Name, UPNSuffix, Sid, AadUserId | Enhanced validation |
| Host | FullName, HostName, DnsDomain, AzureID | Improved correlation |
| IP | Address | Geographic enrichment |
| File | Directory, Name | Enhanced metadata |
| DNS | DomainName | Threat intel integration |
| URL | Url | Expanded validation |
| Process | ProcessId, CommandLine | Behavioral analytics |
| **CloudApplication** | AppId, Name, InstanceName | **Cloud service integration** |
| **Mailbox** | MailboxPrimaryAddress, DisplayName | **Email threat detection** |
| **MailCluster** | NetworkMessageIds, Threats | **Campaign correlation** |
| **MailMessage** | Recipient, Sender, Subject | **Phishing analysis** |
| **SecurityGroup** | DistinguishedName, SID | **Privilege tracking** |
| **AzureResource** | ResourceId | **Resource monitoring** |
| **IoTDevice** | DeviceId, DeviceName | **IoT security** |

**Migration from legacy entity fields:**

```yaml
# ❌ DEPRECATED - Will cause validation errors
query: |
  SigninLogs
  | extend AccountCustomEntity = UserPrincipalName
  | extend IPCustomEntity = IPAddress

# ✅ REQUIRED - Proper entity mapping
entityMappings:
  - entityType: "Account"
    fieldMappings:
      - identifier: "FullName"
        columnName: "UserPrincipalName"
  - entityType: "IP"
    fieldMappings:
      - identifier: "Address"
        columnName: "IPAddress"
```

### Advanced Features (2024-2025 Enhancements)

#### Dynamic Alert Properties

Enhanced alert customization with support for dynamic content based on query results:

```yaml
alertDetailsOverride:
  alertDisplayNameFormat: "{{FailedAttempts}} failed logins from {{IPAddress}} for {{UserPrincipalName}}"
  alertDescriptionFormat: "Detected {{FailedAttempts}} failed attempts from {{Location}} within {{TimeWindow}}"
  alertSeverityColumnName: "CalculatedSeverity"      # Dynamic severity based on query results
  alertTacticsColumnName: "DynamicTactics"           # Dynamic tactics based on attack patterns
```

**Limitations:**

- Maximum 3 parameters in alertDisplayNameFormat (256 char limit)
- Maximum 3 parameters in alertDescriptionFormat (5,000 char limit)
- Column names must match query output exactly

#### Custom Details

Surface critical event data directly in alerts without requiring log investigation:

```yaml
customDetails:
  FailedAttemptCount: "FailedAttempts"               # Number of failed attempts
  SourceLocation: "Location"                        # Geographic location
  TimeWindow: "TimeWindowAnalyzed"                  # Analysis time frame
  RiskScore: "CalculatedRiskScore"                  # Dynamic risk assessment
  AttackChain: "DetectedAttackPattern"              # Attack pattern classification
```

**Limitations:**

- Maximum 20 custom details per rule
- Keys must be alphanumeric with no special characters
- Values must reference valid query column names

#### Enhanced Incident Configuration

Advanced incident creation and grouping with smart correlation:

```yaml
incidentConfiguration:
  createIncident: true
  groupingConfiguration:
    enabled: true
    reopenClosedIncident: false                     # Reopen closed incidents for new alerts
    lookbackDuration: "PT5H"                       # ISO 8601 format required
    matchingMethod: "Selected"                      # AllEntities|AnyAlert|Selected
    groupByEntities: ["Account", "Host", "IP"]      # Group by specific entity types
    groupByAlertDetails: ["AlertName"]              # Group by alert properties
    groupByCustomDetails: ["ThreatLevel", "Campaign"] # Group by custom fields
```

**Capabilities:**

- **Selected matching** allows precise grouping control
- **Custom detail grouping** enables campaign-based correlation
- **Automatic reopening** for ongoing attack scenarios

#### Event Grouping Settings

Control alert generation granularity:

```yaml
eventGroupingSettings:
  aggregationKind: "SingleAlert"     # Generate one alert per query execution
  # OR
  aggregationKind: "AlertPerResult"  # Generate separate alert for each query result
```

#### Suppression Settings (Updated Structure)

**Breaking Change:** The nested `suppressionSettings` object has been flattened:

```yaml
# ❌ DEPRECATED - Will cause validation errors
suppressionSettings:
  suppressionDuration: "PT5H"
  suppressionEnabled: false

# ✅ REQUIRED - Updated flat structure
suppressionDuration: "PT5H"
suppressionEnabled: false
```

### Rule Types (Expanded 2024-2025)

Microsoft Sentinel now supports six distinct rule types, each with specific capabilities:

| Rule Type | Description | Use Case |
|-----------|-------------|----------|
| **Scheduled** | Traditional time-based queries | Custom KQL-based detections |
| **NRT** | Near Real-Time (2-minute frequency) | High-priority, low-latency alerts |
| **Fusion** | ML-based multi-stage attack detection | Advanced persistent threats |
| **MLBehaviorAnalytics** | User/entity behavioral analysis | Insider threat detection |
| **ThreatIntelligence** | Indicator matching (STIX 2.1) | IOC-based detection |
| **MicrosoftSecurityIncidentCreation** | Microsoft alert correlation | Unified incident management |

**ThreatIntelligence Rule Migration (Critical):**

```yaml
# Example ThreatIntelligence rule with new schema
kind: "ThreatIntelligence"
query: |
  ThreatIntelIndicators
  | where IsDeleted == false
  | where Data.pattern_type == "stix-pattern"
  | join kind=inner (
    CommonSecurityLog
    | where TimeGenerated > ago(1h)
  ) on $left.Data.pattern == $right.DestinationIP
```

Hunting queries are exploratory and should be flexible with time ranges:

```yaml
# ✅ For hunting - let UI control time range
SigninLogs
| where ResultType != 0
| summarize by UserPrincipalName, IPAddress

# ✅ For complex hunting with specific lookback
let starttime = todatetime('{{StartTimeISO}}');
let endtime = todatetime('{{EndTimeISO}}');
let lookback = starttime - 7d;

SigninLogs
| where TimeGenerated between (lookback .. endtime)
```

### Hunting Query Template

```yaml
id: "hunting-guid-here"
name: "Hunt for Suspicious Activity"
description: |
  'Hunting query to identify potential threats in the environment.'
requiredDataConnectors:
  - connectorId: "AzureActiveDirectory"
    dataTypes:
      - "SigninLogs"
tactics:
  - "InitialAccess"
relevantTechniques:
  - "T1078"
query: |
  // Hunting query here
entityMappings:
  - entityType: "Account"
    fieldMappings:
      - identifier: "FullName"
        columnName: "UserPrincipalName"
```

## 🚀 Deployment

### Configuration File

Create `sentinel-deployment.config` in repository root:

```json
{
  "prioritizedcontentfiles": [
    "Playbooks/Critical-Response-Playbook/azuredeploy.json"
  ],
  "excludecontentfiles": [
    "Detections/Legacy/OldRule.yaml"
  ],
  "parameterfilemappings": {
    "workspace-id-guid": {
      "Playbooks/MyPlaybook/azuredeploy.json": "parameters/myplaybook.parameters.json"
    }
  }
}
```

### Parameter Files

Parameter files follow naming conventions:

1. **Explicit mapping**: Defined in `sentinel-deployment.config`
2. **Workspace-specific**: `template.parameters-{workspaceId}.json`
3. **Default**: `template.parameters.json`

### Deployment Technology Updates

#### Bicep Template Support

Microsoft Sentinel now supports **Bicep templates** alongside ARM JSON for easier deployment:

```yaml
# Repository connections created before Nov 1, 2024 must be recreated
# to support Bicep template deployment capabilities
```

**Bicep advantages:**

- Cleaner, more readable syntax
- Better maintainability and version control
- Improved tooling and IntelliSense support
- Easier parameter management

#### Template Format Conversion

```powershell
# Enhanced conversion with new features
Convert-SentinelARYamlToArm -Filename "rule.yaml" -UseOriginalFilename -IncludeCustomDetails
Convert-SentinelARArmToYaml -Filename "rule.json" -UseOriginalFilename -PreserveBicep
```

#### API Version Updates

| API Version | Features | Recommended Use |
|-------------|----------|----------------|
| `2024-09-01` | Stable features, enhanced entity mapping | Production deployments |
| `2024-01-01-preview` | AI-powered MITRE tagging, sub-techniques | Testing new capabilities |
| `2023-12-01-preview` | Custom details, advanced grouping | Legacy compatibility |

#### Critical Migration Deadlines

🚨 **Action Required by July 31, 2025:**

1. **Audit all analytics rules** for threat intelligence dependencies
2. **Update KQL queries** to use new `ThreatIntelIndicators` table
3. **Migrate workbooks and automation** to STIX 2.1 schema
4. **Test all modified rules** in development environment
5. **Document migration status** for compliance tracking

**Extended support options:**

- Dual ingestion available for up to 12 months past deadline
- Final retirement of legacy tables: May 31, 2026
- Migration assistance tools available in Microsoft documentation

## 🤖 Playbook Management

### Setting Permissions

Use the provided scripts for permission management:

#### Microsoft Sentinel Permissions

```powershell
# Run Set-RoleAssignments.ps1 for Sentinel-specific permissions
.\Set-RoleAssignments.ps1
```

#### Entra ID Permissions

```powershell
# Run Set-EntraPermissions.ps1 for Graph API permissions
.\Set-EntraPermissions.ps1
```

Replace placeholders:

- `<Your Tenant Id>`: Your Azure AD tenant ID
- `<Your Managed Identity ObjectId>`: Playbook's managed identity object ID

## 🔧 Maintenance

### Removing Duplicate Rules

Use `Set-SpecifiedRules.ps1` to clean up duplicate detections:

```powershell
# Configure the script with your GUIDs and paths
$guids = @("guid1", "guid2", "guid3")
$searchPath = "C:\YourRepo\Detections"
.\Set-SpecifiedRules.ps1
```

### Version Management

- **Custom rules**: Start at `0.0.1`, increment as needed
- **Modified solution rules**: Document changes clearly
- **Regular updates**: Review and update rules quarterly

## 📚 Reference

### Data Connector Mappings

| Connector ID | Data Types |
|--------------|------------|
| AzureActiveDirectory | SigninLogs, AuditLogs |
| AzureSecurityCenter | SecurityAlert (ASC) |
| Office365 | OfficeActivity |
| SecurityEvents | SecurityEvent |
| DNS | DnsEvents, DnsInventory |

### MITRE ATT&CK Framework Updates

Microsoft Sentinel now supports **MITRE ATT&CK Framework v16** with enhanced capabilities:

#### Updated Framework Support

- **Added tactics**: Resource Development, Impair Process Control, Inhibit Response Function
- **Sub-techniques**: Now supported with dot notation (e.g., `T1078.001`)
- **AI-powered tagging**: Automatic MITRE mapping suggestions based on KQL analysis

#### Template Format Updates

```yaml
# Current format (v16 support)
tactics: 
  - "InitialAccess"
  - "LateralMovement"
  - "ResourceDevelopment"        # Added in v16
techniques:                      # Updated field name
  - "T1078"                      # Valid Accounts
  - "T1078.001"                  # Default Accounts (sub-technique)
  - "T1078.002"                  # Domain Accounts (sub-technique)

# ⚠️ Legacy format (still supported but deprecated)
relevantTechniques:              # Being phased out
  - "T1078"
```

#### AI-Powered MITRE Tagging (Preview)

Enable automatic MITRE ATT&CK suggestions by including the preview API version:

```yaml
# Use API version 2024-01-01-preview for AI features
apiVersion: "2024-01-01-preview"
```

**Benefits:**

- Reduces manual effort in MITRE mapping
- Improves detection accuracy and coverage
- Provides consistent tagging across security teams
- Identifies gaps in attack technique coverage

### Time Formats

| Context | Format | Example |
|---------|--------|---------|
| YAML | KQL TimeSpan | `1d`, `5m`, `2h` |
| ARM | ISO 8601 | `PT1H`, `P1D` |

### Severity Guidelines

| Level | Description |
|-------|-------------|
| **Informational** | Contextual information, no immediate threat |
| **Low** | Minimal impact, requires multiple steps for damage |
| **Medium** | Limited impact or requires additional activity |
| **High** | Wide-ranging access or immediate environment impact |

---

## 💡 Quick Tips (Updated 2024-2025)

- **Immediately audit threat intelligence rules** - July 31, 2025 deadline approaching
- **Migrate to ISO 8601 time formats** - Legacy formats deprecated
- **Implement mandatory entity mappings** - Required for all new rules
- **Use new custom details fields** - Improve analyst efficiency
- **Test with MITRE ATT&CK v16** - Leverage sub-techniques and new tactics
- **Consider Bicep templates** - Easier deployment and maintenance
- **Enable AI-powered MITRE tagging** - Reduce manual mapping effort
- **Plan repository recreation** - Required for Bicep support if created before Nov 2024
- **Validate templates early** - Enhanced validation catches more issues
- **Document breaking changes** - Track migration progress for compliance

## 🆘 Troubleshooting

### Common Issues (Updated for 2024-2025)

1. **Entity mapping validation errors**: Ensure all templates include proper entityMappings section
2. **Threat intelligence query failures**: Update to new ThreatIntelIndicators table format
3. **Time format errors**: Use ISO 8601 format (PT1H, P1D) instead of legacy formats
4. **Suppression settings structure errors**: Use flat properties instead of nested object
5. **MITRE technique validation**: Verify techniques exist in ATT&CK Framework v16
6. **Custom details key naming**: Use alphanumeric characters only, no special characters
7. **Repository connection issues**: Recreate connections for Bicep template support
8. **API version compatibility**: Use 2024-09-01 for stable features, preview for new capabilities

### Critical Validations

Before deploying any template, verify:

✅ **Entity mappings present and properly formatted**
✅ **Time values in ISO 8601 format**  
✅ **No legacy suppressionSettings object structure**
✅ **MITRE techniques valid in framework v16**
✅ **No references to deprecated ThreatIntelligenceIndicator table**
✅ **Custom details within 20 field limit**
✅ **Query under 10,000 character limit**

### Getting Help

- Review query logs in Log Analytics
- Test queries in Sentinel hunting interface
- Check Azure DevOps pipeline logs
- Validate YAML syntax before committing

---

*This guide covers the essential aspects of Microsoft Sentinel detection management. For the latest updates and detailed API references, consult the official Microsoft Sentinel documentation.*