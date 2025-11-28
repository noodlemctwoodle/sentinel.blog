# UniFi Site Manager Connector for Microsoft Sentinel

A Codeless Connector Framework (CCF) data connector that ingests UniFi network data from the official [UniFi Site Manager API](https://developer.ui.com/site-manager-api/gettingstarted) into Microsoft Sentinel.

## Overview

This connector enables security monitoring and network visibility for UniFi deployments by collecting data from the UniFi Site Manager API (api.ui.com). The Site Manager API provides programmatic access to monitor and manage UniFi deployments at scale.

### Data Tables

| Table | Description | Default Polling |
|-------|-------------|-----------------|
| `UniFiSiteManager_Hosts_CL` | UniFi consoles and controllers (UDM, UCK, self-hosted) | 5 minutes |
| `UniFiSiteManager_Sites_CL` | Site configurations, device counts, and client statistics | 5 minutes |
| `UniFiSiteManager_Devices_CL` | Network device inventory, status, and firmware info | 5 minutes |
| `UniFiSiteManager_ISPMetrics_CL` | Internet performance metrics (latency, packet loss, uptime) | 60 minutes |

### Connector Features

- **Parameterised deployment** - Configure DCE, DCR, and table names
- **Configurable polling intervals** - Adjust data collection frequency
- **Comprehensive sample queries** - Pre-built KQL queries for common scenarios
- **Detailed documentation** - In-connector guidance for data structure and usage

## Prerequisites

1. **Microsoft Sentinel workspace** with appropriate permissions
2. **Data Collection Endpoint (DCE)** configured in your resource group
3. **UniFi Site Manager API Key** from [unifi.ui.com](https://unifi.ui.com)

### Getting Your UniFi API Key

1. Sign in to [UniFi Site Manager](https://unifi.ui.com) with your UI account
2. Click **API** in the left navigation bar
3. Click **Create API Key**
4. Copy and securely store the key (it's only shown once)

> **Note**: The API key is currently read-only and is tied to your UI account. It provides access to all hosts and sites you own or have super admin permissions for.

### API Rate Limits

| API Version | Rate Limit |
|-------------|------------|
| v1 stable (`/v1/`) | 10,000 requests/minute |
| Early Access (`/ea/`) | 100 requests/minute |

## Deployment

### Parameters

All connectors accept the following parameters:

| Parameter | Required | Description | Default |
|-----------|----------|-------------|---------|
| `workspace` | Yes | Log Analytics workspace name | - |
| `workspace-location` | Yes | Region of the Log Analytics workspace | - |
| `dataCollectionEndpointName` | Yes | Name of your existing DCE | - |
| `dataCollectionRuleName` | No | Name for the DCR | `UniFiSiteManager-{Type}-DCR` |
| `tableName` | No | Custom log table name | `UniFiSiteManager_{Type}_CL` |
| `pollingIntervalMinutes` | No | Polling frequency (minutes) | 5 (60 for ISP Metrics) |

### Option 1: Deploy to Azure (Recommended)

Deploy individual connectors using the buttons below:

| Connector | Deploy |
|-----------|--------|
| Devices | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnoodlemctwoodle%2Fsentinel.blog%2Fmain%2FMicrosoftSentinel%2FCodelessConnectorFramework%2FUnifi%2Fazuredeploy_devices.json) |
| Hosts | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnoodlemctwoodle%2Fsentinel.blog%2Fmain%2FMicrosoftSentinel%2FCodelessConnectorFramework%2FUnifi%2Fazuredeploy_hosts.json) |
| Sites | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnoodlemctwoodle%2Fsentinel.blog%2Fmain%2FMicrosoftSentinel%2FCodelessConnectorFramework%2FUnifi%2Fazuredeploy_sites.json) |
| ISP Metrics | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnoodlemctwoodle%2Fsentinel.blog%2Fmain%2FMicrosoftSentinel%2FCodelessConnectorFramework%2FUnifi%2Fazuredeploy_isp_metrics.json) |

### Option 2: Azure CLI

```bash
# Clone the repository
git clone https://github.com/noodlemctwoodle/sentinel.blog.git
cd sentinel.blog/MicrosoftSentinel/CodelessConnectorFramework/Unifi

# Deploy Devices connector
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file azuredeploy_devices.json \
  --parameters \
    workspace=<your-workspace-name> \
    workspace-location=<workspace-region> \
    dataCollectionEndpointName=<your-dce-name>

# Deploy Hosts connector
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file azuredeploy_hosts.json \
  --parameters \
    workspace=<your-workspace-name> \
    workspace-location=<workspace-region> \
    dataCollectionEndpointName=<your-dce-name>

# Deploy Sites connector
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file azuredeploy_sites.json \
  --parameters \
    workspace=<your-workspace-name> \
    workspace-location=<workspace-region> \
    dataCollectionEndpointName=<your-dce-name>

# Deploy ISP Metrics connector
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file azuredeploy_isp_metrics.json \
  --parameters \
    workspace=<your-workspace-name> \
    workspace-location=<workspace-region> \
    dataCollectionEndpointName=<your-dce-name> \
    metricInterval=1h \
    pollingIntervalMinutes=60
```

### Option 3: PowerShell

```powershell
# Clone the repository
git clone https://github.com/noodlemctwoodle/sentinel.blog.git
Set-Location sentinel.blog/MicrosoftSentinel/CodelessConnectorFramework/Unifi

# Deploy all connectors
$params = @{
    ResourceGroupName = "<your-resource-group>"
    workspace = "<your-workspace-name>"
    "workspace-location" = "<workspace-region>"
    dataCollectionEndpointName = "<your-dce-name>"
}

# Devices
New-AzResourceGroupDeployment @params -TemplateFile "azuredeploy_devices.json"

# Hosts
New-AzResourceGroupDeployment @params -TemplateFile "azuredeploy_hosts.json"

# Sites
New-AzResourceGroupDeployment @params -TemplateFile "azuredeploy_sites.json"

# ISP Metrics (with custom interval)
New-AzResourceGroupDeployment @params `
    -TemplateFile "azuredeploy_isp_metrics.json" `
    -metricInterval "1h" `
    -pollingIntervalMinutes 60
```

### Option 4: Manual ARM Template Deployment

1. Navigate to the Azure Portal
2. Go to **Deploy a custom template**
3. Select **Build your own template in the editor**
4. Paste the contents of the desired connector JSON file from [GitHub](https://github.com/noodlemctwoodle/sentinel.blog/tree/main/MicrosoftSentinel/CodelessConnectorFramework/Unifi)
5. Fill in the required parameters
6. Review and create

## Post-Deployment Configuration

1. Navigate to **Microsoft Sentinel** > **Data connectors**
2. Search for **UniFi Site Manager**
3. Open the connector page for each deployed connector
4. Enter your UniFi API Key
5. Click **Connect**

> **Note**: Data may take up to 30 minutes to appear after initial connection.

## Data Schema Reference

### UniFiSiteManager_Hosts_CL

Hosts are UniFi consoles and controllers that manage your network.

| Column | Type | Description |
|--------|------|-------------|
| `TimeGenerated` | datetime | Event generation time |
| `id` | string | Unique host identifier |
| `hardwareId` | string | Hardware identifier |
| `hostType` | string | Host type (`ucore`, `uck`, `self-hosted`) |
| `ipAddress` | string | Host IP address |
| `owner` | boolean | Whether API caller owns this host |
| `isBlocked` | boolean | Whether host is blocked |
| `registrationTime` | string | Host registration timestamp |
| `lastConnectionStateChange` | string | Last connection state change |
| `latestBackupTime` | string | Latest backup timestamp |
| `userData` | dynamic | User data including apps and console members |
| `reportedState` | dynamic | Host reported state (varies by UniFi OS version) |

**Host Types:**

- `ucore` - UniFi OS Console (UDM, UDR, UDW, UNVR)
- `uck` - UniFi Cloud Key
- `self-hosted` - Self-hosted Network Server

### UniFiSiteManager_Sites_CL

Sites are logical network locations managed by hosts.

| Column | Type | Description |
|--------|------|-------------|
| `TimeGenerated` | datetime | Event generation time |
| `siteId` | string | Unique site identifier |
| `hostId` | string | Host managing this site |
| `meta` | dynamic | Site metadata (name, description, timezone, gatewayMac) |
| `siteStatistics` | dynamic | Site statistics (device counts, client counts) |
| `permission` | string | API caller's permission level |
| `isOwner` | boolean | Whether API caller owns this site |

**Extracting nested fields:**

```kql
UniFiSiteManager_Sites_CL
| extend 
    siteName = tostring(meta.name),
    timezone = tostring(meta.timezone),
    totalDevices = toint(siteStatistics.counts.totalDevice),
    wifiClients = toint(siteStatistics.counts.wifiClient)
```

### UniFiSiteManager_Devices_CL

Devices are the UniFi network equipment managed by hosts.

| Column | Type | Description |
|--------|------|-------------|
| `TimeGenerated` | datetime | Event generation time |
| `id` | string | Unique device identifier |
| `mac` | string | Device MAC address |
| `name` | string | Device name |
| `model` | string | Device model identifier |
| `shortname` | string | Device short name |
| `ip` | string | Device IP address |
| `productLine` | string | Product line (`network`, `protect`, `access`, `talk`) |
| `status` | string | Device status (`online`, `offline`, `updating`) |
| `version` | string | Firmware version |
| `firmwareStatus` | string | Firmware update status |
| `updateAvailable` | string | Available firmware version |
| `isConsole` | boolean | Whether device is a console |
| `isManaged` | boolean | Whether device is managed |
| `startupTime` | string | Device startup timestamp |
| `adoptionTime` | string | Device adoption timestamp |
| `note` | string | User-defined device note |
| `uidb` | dynamic | UniFi device database metadata |

### UniFiSiteManager_ISPMetrics_CL

ISP metrics provide internet connection health data.

| Column | Type | Description |
|--------|------|-------------|
| `TimeGenerated` | datetime | Event generation time |
| `metricType` | string | Metric aggregation interval |
| `hostId` | string | Host identifier |
| `siteId` | string | Site identifier |
| `periods` | dynamic | Array of metric periods |

**Expanding metric periods:**

```kql
UniFiSiteManager_ISPMetrics_CL
| mv-expand period = periods
| extend 
    metricTime = todatetime(period.metricTime),
    avgLatency = toint(period.data.wan.avgLatency),
    maxLatency = toint(period.data.wan.maxLatency),
    packetLoss = toint(period.data.wan.packetLoss),
    downloadMbps = todouble(period.data.wan.download_kbps) / 1000,
    uploadMbps = todouble(period.data.wan.upload_kbps) / 1000,
    uptime = toint(period.data.wan.uptime),
    downtime = toint(period.data.wan.downtime),
    ispName = tostring(period.data.wan.ispName),
    ispAsn = tostring(period.data.wan.ispAsn),
    firmwareVersion = tostring(period.version)
```

**Period fields:**

| Field | Description |
|-------|-------------|
| `start` / `end` | Period timestamps |
| `latency.avg` | Average latency (ms) |
| `packetLoss` | Packet loss percentage |
| `download` | Download speed (kbps) |
| `upload` | Upload speed (kbps) |
| `uptime` | Connection uptime percentage |

## Sample KQL Queries

### Device Inventory Overview

```kql
UniFiSiteManager_Devices_CL
| summarize 
    TotalDevices = dcount(id),
    OnlineDevices = dcountif(id, status == "online"),
    OfflineDevices = dcountif(id, status != "online")
    by productLine
| extend OfflinePercentage = round(100.0 * OfflineDevices / TotalDevices, 2)
```

### Devices Requiring Firmware Updates

```kql
UniFiSiteManager_Devices_CL
| where isnotempty(updateAvailable)
| project 
    TimeGenerated, 
    name, 
    model, 
    version,
    updateAvailable,
    firmwareStatus
| sort by name asc
```

### Offline Devices

```kql
UniFiSiteManager_Devices_CL
| where status != "online"
| project 
    TimeGenerated, 
    name, 
    model, 
    ip, 
    status,
    productLine
| sort by TimeGenerated desc
```

### Device Model Distribution

```kql
UniFiSiteManager_Devices_CL
| summarize Count = dcount(id) by model, productLine
| sort by Count desc
| render piechart
```

### Host Connection State Changes (Last 24h)

```kql
UniFiSiteManager_Hosts_CL
| where isnotempty(lastConnectionStateChange)
| extend ConnectionChange = todatetime(lastConnectionStateChange)
| where ConnectionChange > ago(24h)
| project TimeGenerated, id, hostType, ipAddress, ConnectionChange
| sort by ConnectionChange desc
```

### Hosts by Application Type

```kql
UniFiSiteManager_Hosts_CL
| extend Apps = userData.apps
| mv-expand Apps
| summarize HostCount = dcount(id) by tostring(Apps)
| sort by HostCount desc
```

### Site Health Dashboard

```kql
UniFiSiteManager_Sites_CL
| extend 
    siteName = tostring(meta.name),
    totalDevices = toint(siteStatistics.counts.totalDevice),
    offlineDevices = toint(siteStatistics.counts.offlineDevice),
    wifiClients = toint(siteStatistics.counts.wifiClient),
    wiredClients = toint(siteStatistics.counts.wiredClient)
| project 
    TimeGenerated,
    siteName, 
    totalDevices, 
    offlineDevices,
    TotalClients = wifiClients + wiredClients
| sort by offlineDevices desc
```

### Sites by Permission Level

```kql
UniFiSiteManager_Sites_CL
| summarize SiteCount = dcount(siteId) by permission
| sort by SiteCount desc
```

### ISP Performance - High Latency Events

```kql
UniFiSiteManager_ISPMetrics_CL
| mv-expand period = periods
| extend avgLatency = toint(period.data.wan.avgLatency)
| where avgLatency > 100
| project TimeGenerated, hostId, siteId, avgLatency
| sort by avgLatency desc
```

### ISP Performance - Packet Loss Events

```kql
UniFiSiteManager_ISPMetrics_CL
| mv-expand period = periods
| extend packetLoss = toint(period.data.wan.packetLoss)
| where packetLoss > 1
| project TimeGenerated, hostId, siteId, packetLoss
| sort by packetLoss desc
```

### ISP Uptime Summary by Site

```kql
UniFiSiteManager_ISPMetrics_CL
| mv-expand period = periods
| extend uptime = toint(period.data.wan.uptime)
| summarize 
    AvgUptime = avg(uptime), 
    MinUptime = min(uptime),
    Measurements = count()
    by siteId
| extend UptimeSLA = iff(AvgUptime >= 99.9, "✅ Met", "❌ Not Met")
| sort by AvgUptime asc
```

### Speed Test Trends Over Time

```kql
UniFiSiteManager_ISPMetrics_CL
| mv-expand period = periods
| extend 
    periodStart = todatetime(period.metricTime),
    downloadMbps = todouble(period.data.wan.download_kbps) / 1000,
    uploadMbps = todouble(period.data.wan.upload_kbps) / 1000
| summarize 
    AvgDownload = avg(downloadMbps), 
    AvgUpload = avg(uploadMbps) 
    by bin(periodStart, 1h)
| sort by periodStart asc
| render timechart
```

## Analytics Rules (Examples)

### Device Went Offline

```kql
// Run every 5 minutes, look back 10 minutes
UniFiSiteManager_Devices_CL
| where TimeGenerated > ago(10m)
| where status != "online"
| project 
    TimeGenerated,
    name,
    model,
    ip,
    mac,
    productLine
```

### High Packet Loss Detected

```kql
// Run every 15 minutes, look back 20 minutes
UniFiSiteManager_ISPMetrics_CL
| where TimeGenerated > ago(20m)
| mv-expand period = periods
| extend packetLoss = toint(period.data.wan.packetLoss)
| where packetLoss > 5
| project 
    TimeGenerated,
    siteId,
    packetLoss
```

### Host Connection Lost

```kql
// Run every 5 minutes, look back 10 minutes
UniFiSiteManager_Hosts_CL
| where TimeGenerated > ago(10m)
| where isBlocked == true
| project 
    TimeGenerated,
    id,
    hostType,
    ipAddress
```

### Firmware Update Available (Daily Summary)

```kql
// Run daily
UniFiSiteManager_Devices_CL
| where TimeGenerated > ago(1d)
| where isnotempty(updateAvailable)
| summarize arg_max(TimeGenerated, *) by id
| project 
    name,
    model,
    version,
    updateAvailable
```

### New Device Adopted

```kql
// Run every 15 minutes, look back 20 minutes
UniFiSiteManager_Devices_CL
| where TimeGenerated > ago(20m)
| where isnotempty(adoptionTime)
| extend AdoptionDate = todatetime(adoptionTime)
| where AdoptionDate > ago(1h)
| project 
    TimeGenerated,
    name,
    model,
    ip,
    AdoptionDate
```

## API Endpoints Used

| Endpoint | Method | Description | Rate Limit |
|----------|--------|-------------|------------|
| `/v1/hosts` | GET | List all UniFi hosts | 10,000/min |
| `/v1/sites` | GET | List all UniFi sites | 10,000/min |
| `/v1/devices` | GET | List all UniFi devices | 10,000/min |
| `/ea/isp-metrics/{interval}` | GET | Get ISP metrics (5m or 1h) | 100/min |

> **Note**: The `/ea/` (Early Access) endpoints may change. Monitor the [UniFi API documentation](https://developer.ui.com/) for updates.

## Troubleshooting

### No Data Appearing

1. **Verify API key** - Ensure the key is correct and hasn't been revoked
2. **Check DCE configuration** - Verify the Data Collection Endpoint exists and is accessible
3. **Wait for ingestion** - Initial data may take up to 30 minutes to appear
4. **Check DCR status** - Review the Data Collection Rule in Azure Monitor for errors
5. **Verify permissions** - Ensure workspace has read/write permissions

### Rate Limiting (429 Errors)

The connector handles rate limiting automatically with retry logic. If you see persistent 429 errors:

1. Increase `pollingIntervalMinutes` to reduce request frequency
2. For ISP Metrics, use `1h` interval instead of `5m`
3. Check if multiple connectors are using the same API key

### Connection Issues

1. **API key expired** - Create a new key at unifi.ui.com
2. **Network connectivity** - Ensure Azure can reach `api.ui.com`
3. **DCR errors** - Check Azure Monitor logs for transformation or ingestion errors

### Data Quality Issues

1. **Missing fields** - Some fields vary by UniFi OS version; use `isnotempty()` checks
2. **Dynamic field access** - Use proper dot notation for nested fields in `meta`, `siteStatistics`, `userData`, `periods`
3. **Timestamp parsing** - API returns ISO 8601 strings; use `todatetime()` for conversion

## Repository Structure

```
MicrosoftSentinel/CodelessConnectorFramework/Unifi/
├── README.md                      # This documentation
├── azuredeploy_devices.json       # Devices connector ARM template
├── azuredeploy_hosts.json         # Hosts connector ARM template
├── azuredeploy_sites.json         # Sites connector ARM template
└── azuredeploy_isp_metrics.json   # ISP Metrics connector ARM template
```

## Contributing

Contributions are welcome! Please submit issues and pull requests to [GitHub](https://github.com/noodlemctwoodle/sentinel.blog).

### Development

To test API responses locally:

```bash
# Hosts
curl -s -X GET 'https://api.ui.com/v1/hosts' \
  -H 'X-API-Key: YOUR_API_KEY' \
  -H 'Accept: application/json' | jq '.data[0]'

# Sites
curl -s -X GET 'https://api.ui.com/v1/sites' \
  -H 'X-API-Key: YOUR_API_KEY' \
  -H 'Accept: application/json' | jq '.data[0]'

# Devices
curl -s -X GET 'https://api.ui.com/v1/devices' \
  -H 'X-API-Key: YOUR_API_KEY' \
  -H 'Accept: application/json' | jq '.data[0]'

# ISP Metrics (1 hour aggregation)
curl -s -X GET 'https://api.ui.com/ea/isp-metrics/1h' \
  -H 'X-API-Key: YOUR_API_KEY' \
  -H 'Accept: application/json' | jq '.data[0]'

# ISP Metrics (5 minute aggregation - Early Access)
curl -s -X GET 'https://api.ui.com/ea/isp-metrics/5m' \
  -H 'X-API-Key: YOUR_API_KEY' \
  -H 'Accept: application/json' | jq '.data[0]'
```

## License

This project is licensed under the MIT License.

## Acknowledgments

- [Microsoft Sentinel CCF Documentation](https://learn.microsoft.com/en-us/azure/sentinel/create-codeless-connector)
- [UniFi Site Manager API Documentation](https://developer.ui.com/site-manager-api/gettingstarted)
- [UniFi Developer Portal](https://developer.ui.com/)
- [Sentinel.blog](https://sentinel.blog)

**Key updates:**

1. **Fixed Deploy to Azure URLs** - Now pointing to the correct raw GitHub URLs:
   - `https://raw.githubusercontent.com/noodlemctwoodle/sentinel.blog/main/MicrosoftSentinel/CodelessConnectorFramework/Unifi/azuredeploy_devices.json`
   - `https://raw.githubusercontent.com/noodlemctwoodle/sentinel.blog/main/MicrosoftSentinel/CodelessConnectorFramework/Unifi/azuredeploy_hosts.json`
   - `https://raw.githubusercontent.com/noodlemctwoodle/sentinel.blog/main/MicrosoftSentinel/CodelessConnectorFramework/Unifi/azuredeploy_sites.json`
   - `https://raw.githubusercontent.com/noodlemctwoodle/sentinel.blog/main/MicrosoftSentinel/CodelessConnectorFramework/Unifi/azuredeploy_isp_metrics.json`

2. **Updated file references** - Changed to match actual filenames (`azuredeploy_devices.json` instead of `UniFiSiteManager-Devices.json`)

3. **Added git clone instructions** - CLI and PowerShell examples now include cloning the repository first

4. **Added repository structure** - Shows the actual folder layout

5. **Updated contributing section** - Links to the correct GitHub repository

6. **Added Sentinel.blog acknowledgment**