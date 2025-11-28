# UniFi Site Manager - Microsoft Sentinel Analytics Rules

A collection of analytics rules for monitoring UniFi network infrastructure through Microsoft Sentinel.

**Author:** [Fetch Labs](https://sentinel.blog)  
**Version:** 1.0.0

## Overview

These analytics rules provide comprehensive monitoring for UniFi Site Manager data ingested into Microsoft Sentinel. They detect device health issues, ISP performance problems, security events, and data connector health.

## Prerequisites

- Microsoft Sentinel workspace
- UniFi Site Manager data connectors deployed:
  - `UniFiSiteManager_Devices_CL`
  - `UniFiSiteManager_Hosts_CL`
  - `UniFiSiteManager_Sites_CL`
  - `UniFiSiteManager_ISPMetrics_CL`

## Analytics Rules

### Device Health

| Rule | Severity | Description |
|------|----------|-------------|
| [Device Offline](./UniFi-Device-Offline.json) | Medium | Detects when a device goes offline |
| [Multiple Devices Offline](./UniFi-Multiple-Devices-Offline.json) | High | Detects mass offline events indicating network-wide issues |
| [New Device Adopted](./UniFi-New-Device-Adopted.json) | Informational | Detects new devices added to the network |

### Firmware & Security

| Rule | Severity | Description |
|------|----------|-------------|
| [Firmware Update Available](./UniFi-Firmware-Update-Available.json) | Low | Detects devices with pending firmware updates |

### ISP Performance

| Rule | Severity | Description |
|------|----------|-------------|
| [ISP High Latency](./UniFi-ISP-High-Latency.json) | Medium | Detects when latency exceeds thresholds |
| [ISP Packet Loss](./UniFi-ISP-Packet-Loss.json) | Medium | Detects packet loss on WAN connection |
| [ISP Downtime](./UniFi-ISP-Downtime.json) | High | Detects ISP outages |
| [ISP SLA Breach](./UniFi-ISP-SLA-Breach.json) | Medium | Detects when uptime falls below SLA target |

### Controller & Site Health

| Rule | Severity | Description |
|------|----------|-------------|
| [Controller Connection Change](./UniFi-Controller-Connection-Change.json) | Medium | Detects controller connection state changes |
| [Site Health Critical](./UniFi-Site-Health-Critical.json) | High | Detects sites with multiple offline devices |

### Data Connector Health

| Rule | Severity | Description |
|------|----------|-------------|
| [Data Connector Health](./UniFi-Data-Connector-Health.json) | Medium | Monitors data ingestion health |

## Deployment

### Deploy Individual Rule via Azure CLI

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-file <rule-template>.json \
  --parameters workspace=<workspace-name>
```

### Deploy via PowerShell

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "<resource-group>" `
  -TemplateFile "UniFi-Device-Offline.json" `
  -workspace "<workspace-name>"
```

### Deploy via Azure Portal

1. Navigate to your Resource Group
2. Click **Deploy a custom template**
3. Click **Build your own template in the editor**
4. Paste the JSON content from the rule file
5. Click **Save**
6. Enter your workspace name
7. Click **Review + create**

### Import via Microsoft Sentinel

1. Navigate to Microsoft Sentinel
2. Select **Analytics** under Configuration
3. Click **Import** from the top bar
4. Select the JSON file to import
5. Click **Open**

## Thresholds

Default thresholds are configured in each rule's KQL query. To modify, edit the `let` statements at the beginning of each query:

| Rule | Variable | Default | Description |
|------|----------|---------|-------------|
| Device Offline | `OfflineMinutes` | 10 | Minutes offline before alerting |
| Multiple Devices Offline | `OfflineThreshold` | 3 | Devices required to trigger |
| Firmware Update | `DeviceThreshold` | 1 | Devices with updates |
| ISP High Latency | `AvgLatencyThreshold` | 100ms | Average latency threshold |
| ISP High Latency | `MaxLatencyThreshold` | 500ms | Maximum latency threshold |
| ISP Packet Loss | `PacketLossThreshold` | 1 | Packet loss events |
| ISP SLA Breach | `SLAThreshold` | 99.9% | Uptime target |
| Site Health Critical | `OfflineThreshold` | 3 | Offline devices per site |
| Data Connector Health | `StaleThreshold` | 30 | Minutes without data |

## Query Frequency & Period

| Rule | Frequency | Period |
|------|-----------|--------|
| Device Offline | 15 minutes | 1 hour |
| Multiple Devices Offline | 15 minutes | 30 minutes |
| New Device Adopted | 1 hour | 1 hour |
| Firmware Update Available | 1 day | 1 day |
| ISP High Latency | 15 minutes | 30 minutes |
| ISP Packet Loss | 15 minutes | 30 minutes |
| ISP Downtime | 15 minutes | 30 minutes |
| ISP SLA Breach | 1 hour | 1 hour |
| Controller Connection Change | 15 minutes | 1 hour |
| Site Health Critical | 15 minutes | 30 minutes |
| Data Connector Health | 15 minutes | 2 hours |

## MITRE ATT&CK Mapping

| Rule | Tactics | Techniques | Sub-Techniques |
|------|---------|------------|----------------|
| Device Offline | Impact | T1489 | - |
| Multiple Devices Offline | Impact | T1489, T1499 | T1499.004 |
| New Device Adopted | Initial Access, Persistence | T1200, T1133 | - |
| Firmware Update Available | Initial Access | T1190 | - |
| ISP High Latency | Impact | T1498, T1499 | T1498.001 |
| ISP Packet Loss | Impact | T1498, T1499 | T1498.001 |
| ISP Downtime | Impact | T1489, T1499 | T1499.004 |
| ISP SLA Breach | Impact | T1499 | T1499.004 |
| Controller Connection Change | Impact, Command and Control | T1489, T1071 | T1071.001 |
| Site Health Critical | Impact | T1489, T1499 | T1499.004 |
| Data Connector Health | Defense Evasion | T1562 | T1562.001 |

## Incident Grouping

All rules include intelligent incident grouping to reduce alert fatigue:

- **Device-based rules**: Group by Host entity
- **Site-based rules**: Group by SiteId custom detail
- **ISP-based rules**: Group by SiteId and ISPName
- **Connector rules**: Group by TableName

## Customisation

### Adjusting Severity

Edit the `severity` property in the template:

```json
"severity": "High"  // Options: Informational, Low, Medium, High
```

### Adjusting Query Frequency

Edit the `queryFrequency` property (ISO 8601 duration):

```json
"queryFrequency": "PT15M"  // 15 minutes
```

Note: `queryPeriod` must be greater than or equal to `queryFrequency`.

### Adjusting Suppression

Edit suppression settings to control alert frequency:

```json
"suppressionDuration": "PT1H",
"suppressionEnabled": true
```

### Modifying Thresholds

Edit the `let` statements at the beginning of each query:

```kql
let OfflineThreshold = 5;  // Changed from default 3
```

## Alert Details Override

Each rule includes custom alert titles and descriptions. Note that Microsoft Sentinel limits `alertDescriptionFormat` to a maximum of 3 parameters. Additional details are available in `customDetails`.

## Rule IDs

Each rule uses a unique GUID for identification:

| Rule | GUID |
|------|------|
| Device Offline | `a1b2c3d4-1234-5678-9abc-def012345001` |
| Multiple Devices Offline | `a1b2c3d4-1234-5678-9abc-def012345002` |
| New Device Adopted | `a1b2c3d4-1234-5678-9abc-def012345003` |
| Firmware Update Available | `a1b2c3d4-1234-5678-9abc-def012345004` |
| ISP High Latency | `a1b2c3d4-1234-5678-9abc-def012345005` |
| ISP Packet Loss | `a1b2c3d4-1234-5678-9abc-def012345006` |
| ISP Downtime | `a1b2c3d4-1234-5678-9abc-def012345007` |
| ISP SLA Breach | `a1b2c3d4-1234-5678-9abc-def012345008` |
| Controller Connection Change | `a1b2c3d4-1234-5678-9abc-def012345009` |
| Site Health Critical | `a1b2c3d4-1234-5678-9abc-def012345010` |
| Data Connector Health | `a1b2c3d4-1234-5678-9abc-def012345011` |

## Support

- **Documentation**: [sentinel.blog](https://sentinel.blog)
- **Issues**: [GitHub Issues](https://github.com/noodlemctwoodle/sentinel.blog/issues)
- **Source**: [GitHub Repository](https://github.com/noodlemctwoodle/sentinel.blog)

## License

MIT License - See [LICENSE](LICENSE) for details.
