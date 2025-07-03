# Input bindings are passed in via param block for Azure Functions
param($Timer)

# Define the list of Key Vaults to monitor for expiring secrets
$keyVaults = @("<YOUR_KEYVAULT_1>", "<YOUR_KEYVAULT_2>", "<YOUR_KEYVAULT_3>", "<YOUR_KEYVAULT_4>")

# Azure AD App Registration details for authentication
$tenantId = '<YOUR_TENANT_ID>'           # Azure AD tenant ID
$subscriptionId = '<YOUR_SUBSCRIPTION_ID>' # Azure subscription ID
$appId = '<YOUR_APPLICATION_ID>'         # Application (client) ID

# Key Vault configuration for storing secrets and Logic App URI
$vaultName = '<YOUR_KEYVAULT_NAME>'                    # Key Vault name where secrets are stored
$spSecret = '<YOUR_KEYVAULT_SECRET_NAME>'              # Secret name for service principal authentication
$uriSecret = "<YOUR_LOGIC_APP_URI_SECRET>"             # Secret name for Logic App URI

# Retrieve the Logic App URI from Key Vault
$vaultLogicAppUri = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $uriSecret -AsPlainText)

# Initialize array to store details of expiring secrets
$expiringSecrets = @()

# Loop through each Key Vault to check for expiring secrets
foreach ($keyVault in $keyVaults) {
    # Retrieve the service principal secret from Key Vault
    $secret = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $spSecret -AsPlainText)
    
    # Check if the retrieved secret is null or empty
    if ([string]::IsNullOrEmpty($secret)) {
        Write-Host "Secret value is null or empty."
    }
    
    # Convert the retrieved secret to a secure string for authentication
    $securePassword = ConvertTo-SecureString $secret -AsPlainText -Force
    
    # Create PSCredential object with the app ID and secure password
    $creds = New-Object System.Management.Automation.PSCredential($appId, $securePassword)
    
    # Connect to Azure using service principal authentication
    Connect-AzAccount -Credential $creds -Tenant $TenantId -Subscription $subscriptionId -ServicePrincipal -WarningAction SilentlyContinue
    
    # Get all secrets from the current Key Vault that expire within 2 days
    $secrets = Get-AzKeyVaultSecret -VaultName $keyVault |
    Where-Object { $_.Expires -ne $null -and $_.Expires -lt (Get-Date).AddDays(2) } |
    ForEach-Object {
        # Add expiring secret details to the array
        $expiringSecrets += @{
            VaultName = $keyVault
            Name = $_.Name
            Expires = $_.Expires
        }
    }
}

# Check if any secrets are expiring and send notification
if ($expiringSecrets.Count -gt 0) {
    # Convert the expiring secrets array to JSON format
    $jsonBody = $expiringSecrets | ConvertTo-Json
    
    Write-Output "Sending expiring secrets to Logic App"
    
    # Send POST request to Logic App with expiring secrets data
    Invoke-WebRequest -Method Post -Uri $vaultLogicAppUri -Body $jsonBody -ContentType "application/json"
}
else {
    Write-Output "No secrets expiring within 2 days"
}