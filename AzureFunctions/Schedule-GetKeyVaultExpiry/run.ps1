param($Timer)

$keyVaults = @("keyvault1-kv", "keyvault1-kv", "keyvault1-kv", "keyvault1-kv")

$tenantId = '<TenantId>'
$subscriptionId = '<SubscriptionId>'

$appId = '<ApplicationId>'

$vaultName = '<KeyVaultName>'
$spSecret = '<KeyVaultSecretName>'
$uriSecret = "<LogicAppURI>"

$vaultLogicAppUri = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $uriSecret -AsPlainText)

$expiringSecrets = @()

foreach ($keyVault in $keyVaults) {

    $secret = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $spSecret -AsPlainText)
    if ([string]::IsNullOrEmpty($secret)) {
        Write-Host "Secret value is null or empty."
    }

    $securePassword = ConvertTo-SecureString $secret -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential($appId, $securePassword)

    Connect-AzAccount -Credential $creds -Tenant $TenantId -Subscription $subscriptionId -ServicePrincipal -WarningAction SilentlyContinue

    $secrets = Get-AzKeyVaultSecret -VaultName $keyVault |
    Where-Object { $_.Expires -ne $null -and $_.Expires -lt (Get-Date).AddDays(2) } |
    ForEach-Object {
        $expiringSecrets += @{
            VaultName = $keyVault
            Name      = $_.Name
            Expires   = $_.Expires
        }
    }
}

if ($expiringSecrets.Count -gt 0) {
    $jsonBody = $expiringSecrets | ConvertTo-Json
    Write-Output "Sending expiring secrets to Logic App"
    Invoke-WebRequest -Method Post -Uri $vaultLogicAppUri -Body $jsonBody -ContentType "application/json"
}
else {
    Write-Output "No secrets expiring within 2 days"
}