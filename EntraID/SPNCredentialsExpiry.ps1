# Loop through each application
foreach ($app in $applications) {

    # Check Password Credentials (Secrets)
    if ($app.PasswordCredentials) {
        foreach ($secret in $app.PasswordCredentials) {
            if ([string]::IsNullOrEmpty($secret.EndDateTime)) {
                continue
            }
            try {
                $expiryDate = [datetime]::Parse($secret.EndDateTime)
            }
            catch {
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
    
    # Similar check for certificates...
    if ($app.KeyCredentials) {
        foreach ($cert in $app.KeyCredentials) {
            if ([string]::IsNullOrEmpty($cert.EndDateTime)) {
                continue
            }
            try {
                $expiryDate = [datetime]::Parse($cert.EndDateTime)
            }
            catch {
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