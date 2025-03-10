<#
.SYNOPSIS
    Checks Azure AD applications for expiring credentials, outputs a flat JSON payload with a formatted ExpiryDate,
    and sends the JSON payload to a specified Logic App endpoint.

.DESCRIPTION
    This runbook uses Microsoft Graph with a system-assigned managed identity to retrieve Azure AD applications.
    It then checks both password (secret) and key (certificate) credentials for upcoming expiration.
    Each expiring credential is recorded as a separate flat object. The ExpiryDate is formatted as "dd-MM-yyyy HH:mm:ss".
    The resulting JSON is then sent via an HTTP POST to a Logic App URL for further processing (for example, email notification).

.PARAMETER ExpiryThreshold
    Optional. The number of days to check for expiry. Defaults to 15 days.

.PARAMETER LogicAppUrl
    The URL of the Logic App endpoint that will receive the JSON payload.

.EXAMPLE
    .\CheckAzureADAppExpiry.ps1 -ExpiryThreshold 15 -LogicAppUrl "https://prod-00.westeurope.logic.azure.com:443/workflows/..."
#>

param(
    [Parameter(Mandatory = $false)]
    [int]$ExpiryThreshold = 15,
    
    [Parameter(Mandatory = $true)]
    [string]$LogicAppUrl
)

# Connect to Microsoft Graph using the system-assigned managed identity.
try {
    Write-Output "Connecting to Microsoft Graph using system-assigned managed identity..."
    Connect-MgGraph -Identity -NoWelcome
    Write-Output "Connected to Microsoft Graph."
}
catch {
    Write-Error "Failed to connect to Microsoft Graph. $_"
    throw $_
}

# Retrieve all Azure AD applications.
Write-Output "Retrieving Azure AD applications..."
$applications = Get-MgApplication -All

# Array to hold flat results.
$flatResults = @()

# Loop through each application.
foreach ($app in $applications) {

    # Check Password Credentials (Secrets)
    if ($app.PasswordCredentials) {
        foreach ($secret in $app.PasswordCredentials) {
            if ([string]::IsNullOrEmpty($secret.EndDateTime)) {
                Write-Verbose "Secret for application '$($app.DisplayName)' does not have an expiry date set. Skipping."
                continue
            }
            try {
                $expiryDate = [datetime]::Parse($secret.EndDateTime)
            }
            catch {
                Write-Warning "Could not parse secret expiry date '$($secret.EndDateTime)' for application '$($app.DisplayName)'. Skipping."
                continue
            }
            $daysUntilExpiry = ($expiryDate - (Get-Date)).Days
            if ($daysUntilExpiry -le $ExpiryThreshold) { 
                $flatResults += [PSCustomObject]@{
                    ApplicationName = $app.DisplayName
                    ApplicationId   = $app.AppId
                    CredentialType  = "Secret"
                    ExpiryDate      = $expiryDate.ToString("dd-MM-yyyy HH:mm:ss")
                    DaysUntilExpiry = $daysUntilExpiry
                    Status          = if ($daysUntilExpiry -le 0) { "Expired" } else { "Expiring Soon" }
                }
            }
        }
    }
    
    # Check Key Credentials (Certificates)
    if ($app.KeyCredentials) {
        foreach ($cert in $app.KeyCredentials) {
            if ([string]::IsNullOrEmpty($cert.EndDateTime)) {
                Write-Verbose "Certificate for application '$($app.DisplayName)' does not have an expiry date set. Skipping."
                continue
            }
            try {
                $expiryDate = [datetime]::Parse($cert.EndDateTime)
            }
            catch {
                Write-Warning "Could not parse certificate expiry date '$($cert.EndDateTime)' for application '$($app.DisplayName)'. Skipping."
                continue
            }
            $daysUntilExpiry = ($expiryDate - (Get-Date)).Days
            if ($daysUntilExpiry -le $ExpiryThreshold) {  
                $flatResults += [PSCustomObject]@{
                    ApplicationName = $app.DisplayName
                    ApplicationId   = $app.AppId
                    CredentialType  = "Certificate"
                    ExpiryDate      = $expiryDate.ToString("dd-MM-yyyy HH:mm:ss")
                    DaysUntilExpiry = $daysUntilExpiry
                    Status          = if ($daysUntilExpiry -le 0) { "Expired" } else { "Expiring Soon" }
                }
            }
        }
    }
}

# Convert the flat results to JSON.
$jsonOutput = $flatResults | ConvertTo-Json -Depth 3

# Log the JSON output for debugging.
Write-Output "JSON payload generated"
#Write-Output $jsonOutput

# Send the JSON payload to the Logic App URL via HTTP POST.
try {
    Write-Output "Sending JSON payload to Logic App at: $LogicAppUrl"
    $response = Invoke-RestMethod -Uri $LogicAppUrl -Method Post -Body $jsonOutput -ContentType 'application/json'
    Write-Output "Response from Logic App: $($response | ConvertTo-Json -Depth 3)"
}
catch {
    Write-Error "Failed to send JSON payload to Logic App. $_"
}

Write-Output "Runbook execution completed."
