# Close Greenbone/OpenVAS Scanner Incidents

Automatically closes Microsoft Sentinel incidents triggered by Greenbone/OpenVAS vulnerability scanner activity.

## Overview

This Logic App playbook monitors new Sentinel incidents and automatically closes those originating from authorised vulnerability scanning activity. It matches incidents based on configurable alert title patterns and scanner IP addresses.

## How It Works

1. **Triggers** on every new Sentinel incident
2. **Extracts** alert titles from the incident
3. **Matches** incident/alert titles against your configured patterns (case-insensitive)
4. **Validates** source IP entities against your scanner IP allowlist
5. **If both conditions match**:
   - Adds a detailed closure comment
   - Sets classification to `BenignPositive - SuspectedButExpected`
   - Closes the incident
   - Adds tags: `Greenbone`, `OpenVAS`, `VulnerabilityScanner`, `AutoClosed`

## Prerequisites

- Microsoft Sentinel workspace
- Permissions to deploy Logic Apps
- Microsoft Sentinel Responder role (for the Logic App's managed identity)

## Deployment

### Option 1: Azure CLI

```bash
# Set your variables
RESOURCE_GROUP="your-sentinel-rg"
WORKSPACE_NAME="your-sentinel-workspace"

# Deploy the template
az deployment group create \
  --resource-group $RESOURCE_GROUP \
  --template-file azuredeploy.json \
  --parameters azuredeploy.parameters.json \
  --parameters WorkspaceName=$WORKSPACE_NAME
```

### Option 2: PowerShell

```powershell
$ResourceGroup = "your-sentinel-rg"
$WorkspaceName = "your-sentinel-workspace"

New-AzResourceGroupDeployment `
  -ResourceGroupName $ResourceGroup `
  -TemplateFile "azuredeploy.json" `
  -TemplateParameterFile "azuredeploy.parameters.json" `
  -WorkspaceName $WorkspaceName
```

### Option 3: Azure Portal

1. Navigate to **Deploy a custom template**
2. Select **Build your own template in the editor**
3. Paste the contents of `azuredeploy.json`
4. Complete the parameters
5. Deploy

## Post-Deployment Configuration

### 1. Assign Sentinel Responder Role

The Logic App uses a managed identity. Grant it the required permissions:

```bash
# Get the principal ID from deployment output, or:
PRINCIPAL_ID=$(az logic workflow show \
  --resource-group $RESOURCE_GROUP \
  --name "Close-Greenbone-Scanner-Incidents" \
  --query "identity.principalId" -o tsv)

# Assign the role
az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Microsoft Sentinel Responder" \
  --scope "/subscriptions/{sub-id}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
```

### 2. Authorise the API Connection

1. Navigate to the Logic App in Azure Portal
2. Select **API connections**
3. Click on the `azuresentinel-*` connection
4. Select **Edit API connection**
5. Click **Authorise** and sign in
6. Save

### 3. Create an Automation Rule (Optional)

To ensure the playbook runs on specific incidents, create an automation rule:

1. Navigate to **Microsoft Sentinel** → **Automation**
2. Select **Create** → **Automation rule**
3. Configure:
   - **Trigger**: When incident is created
   - **Conditions**: Add any additional filters as required
   - **Actions**: Run playbook → Select `Close-Greenbone-Scanner-Incidents`

## Configuration

### Scanner IP Addresses

Update the `GreenboneScannerIPs` parameter with your scanner IP addresses:

```json
"GreenboneScannerIPs": {
  "value": [
    "10.0.0.100",
    "10.0.0.101",
    "192.168.1.50"
  ]
}
```

### Alert Title Patterns

Update the `AlertTitlePatterns` parameter with incident/alert titles to match. Matching is case-insensitive and partial:

```json
"AlertTitlePatterns": {
  "value": [
    "Exploit attempt detected",
    "Suspicious network activity",
    "Vulnerability scan detected",
    "Port scan detected",
    "OpenVAS",
    "Greenbone"
  ]
}
```

The playbook matches if the incident title OR any related alert title contains any of these patterns.

## Incident Closure Details

| Field | Value |
|-------|-------|
| Status | Closed |
| Classification | BenignPositive - SuspectedButExpected |
| Classification Reason | Greenbone/OpenVAS vulnerability scanner activity |
| Tags | Greenbone, OpenVAS, VulnerabilityScanner, AutoClosed |

The closure comment includes:

- Matched scanner IP address
- Matched alert pattern
- Closure timestamp

## Troubleshooting

### Logic App Not Triggering

- Verify the API connection is authorised
- Confirm the managed identity has the Sentinel Responder role
- Ensure the Logic App is enabled

### Incidents Not Being Closed

- Check the Logic App run history for errors
- Verify scanner IPs are correctly configured
- Confirm the incident title matches expected patterns
- Check that IP entities are being extracted from incidents

### View Run History

```bash
az logic workflow run list \
  --resource-group $RESOURCE_GROUP \
  --workflow-name "Close-Greenbone-Scanner-Incidents" \
  --query "[].{Name:name, Status:status, StartTime:startTime}" \
  -o table
```

## Security Considerations

- Only add trusted scanner IPs to the allowlist
- Review auto-closed incidents periodically
- Consider adding time-based restrictions to limit auto-closure to scheduled scan windows
- Monitor for false negatives (genuine attacks misclassified as scanner activity)

## Files

| File | Description |
|------|-------------|
| `azuredeploy.json` | ARM template for the Logic App |
| `azuredeploy.parameters.json` | Parameters file - update with your values |

## Licence

MIT

## Author

[sentinel.blog](https://sentinel.blog)