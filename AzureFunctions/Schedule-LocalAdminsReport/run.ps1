# Input bindings are passed in via param block.
param($Timer)

# Define your Azure AD App Registration details
$tenantId = '<YOUR_TENANT_ID>'

# Application (client) ID
$appId = '<YOUR_APPLICATION_ID>'

# Define your Key Vault and Secret Name
$vaultName = '<YOUR_KEYVAULT_NAME>'
$secretName = '<YOUR_KEYVAULT_SECRET_NAME>'

# Define Azure Storage account details
$storageAccountName = "<YOUR_STORAGE_ACCOUNT_NAME>"
$containerName = "<YOUR_CONTAINER_NAME>"
$storageSecretName = "<YOUR_STORAGE_SECRET_NAME>"

# Production Workspace
$workspaceName = "<YOUR_WORKSPACE_NAME>"
$workspaceRG = "<YOUR_RESOURCE_GROUP_NAME>"
$subscriptionId = "<YOUR_SUBSCRIPTION_ID>"

# Generate the file name
$tempFolder = $env:TEMP
$fileName = "LocalAdminsReport.json"
$filePath = Join-Path -Path $tempFolder -ChildPath $fileName

function Invoke-NonApprovedLocalAdmins {
    # Retrieve a secret from Azure Key Vault
    $secret = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $secretName -AsPlainText)
    
    # Check if the retrieved secret is null or empty
    if ([string]::IsNullOrEmpty($secret)) {
        Write-Host "Secret value is null or empty."
    }
    
    # Convert the retrieved secret to a secure string
    $securePassword = ConvertTo-SecureString $secret -AsPlainText -Force
    
    # Create a new PSCredential object with the app ID and secure password
    $creds = New-Object System.Management.Automation.PSCredential($appId, $securePassword)
    
    # Connect to an Azure account using the provided credentials, tenant ID, and subscription ID
    Connect-AzAccount -Credential $creds -Tenant $TenantId -Subscription $subscriptionId -ServicePrincipal -WarningAction SilentlyContinue
    
    # Retrieve the Workspace ID of an Azure Operational Insights workspace
    $WorkspaceID = (Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $workspaceRG).CustomerID
    
    # Define a Kusto Query Language (KQL) query to find non-approved local administrators
    $query = "let localAdmins = _GetWatchlist('localAdmins') | project UserPrincipalName = split(tolower(UserPrincipalName), '@')[0];
    DeviceLogonEvents
    | where TimeGenerated >= startofweek(ago(7d)) and TimeGenerated < endofweek(ago(7d))
    | where ActionType == 'LogonSuccess'
    | where IsLocalAdmin == 1
    | where AccountName !in (localAdmins)
    | extend IsLocalLogon = tobool(AdditionalFields.IsLocalLogon)
    | where IsLocalLogon == true
    | summarize by AccountName, ActionType, IsLocalAdmin, IsLocalLogon, DeviceName"
    
    # Invoke the KQL query using Azure Operational Insights and store the results
    $kqlQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query
    
    # Return results
    return $kqlQuery.Results
}

# Call the function
$queryResults = Invoke-NonApprovedLocalAdmins

# Filter out any null values from the query results
$filteredResults = $queryResults |
Where-Object {
    $null -ne $_.AccountName -and
    $null -ne $_.ActionType -and
    $null -ne $_.IsLocalAdmin -and
    $null -ne $_.IsLocalLogon -and
    $null -ne $_.DeviceName
} |
Select-Object AccountName, ActionType, IsLocalAdmin, IsLocalLogon, DeviceName

# Convert the sorted final output to JSON and save to file
$filteredResults | Sort-Object AccountName | ConvertTo-Json | Out-File -FilePath $filePath -Force

# Connect to Azure Key Vault and get the storage account key
$storageAccountKey = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $storageSecretName -AsPlainText)

# Create a storage context
$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey

# Upload the file to Azure Blob Storage
Set-AzStorageBlobContent -File $filePath -Container $containerName -Blob $fileName -Context $context -Force

# Additional logging to confirm script completion
Write-Host "Script execution completed"