# Azure Function Timer Trigger Entry Point
# Executes on a schedule to collect Microsoft 365 Defender security events and forward them to Event Hub
param($Timer)

# Entra ID Authentication Configuration
# Required environment variables for Microsoft Graph API authentication
$tenantId                   = $env:TenantId      # Organisation's Entra Directory ID
$clientId                   = $env:ClientId      # Entra ID App Registration ID for API access
$clientSecret              = $env:ClientSecret   # Secret key for application authentication

# Query and Batch Processing Configuration
$batchSize = 10000         # Maximum records per API request (optimized for M365D API limits)
$lookbackMinutes = "5m"   # Historical data collection window (5 minutes)

# KQL Query Definitions
# Structured queries for different security event types in Microsoft 365 Defender
$queries = @(
    @{ 
        Name = "AntivirusDetection"
        # Collects endpoint antivirus detections within specified timeframe
        KQL = "DeviceEvents 
            | where ActionType == 'AntivirusDetection' 
            | where Timestamp > ago($lookbackMinutes) 
            | order by Timestamp asc 
            | take $batchSize"
    },
    @{ 
        Name = "AlertInfoExcludeDLP"
        # Collects security alerts, filtering out DLP-related events
        KQL = "AlertInfo 
            | where DetectionSource != 'Microsoft Data Loss Protection' 
            | where Timestamp > ago($lookbackMinutes) 
            | order by Timestamp asc 
            | take $batchSize"
    },
    @{ 
        Name = "AlertEvidenceExcludeDLP"
        # Collects evidence for security alerts, excluding DLP-related items
        KQL = "AlertEvidence 
            | where DetectionSource != 'Microsoft Data Loss Protection' 
            | where Timestamp > ago($lookbackMinutes) 
            | order by Timestamp asc 
            | take $batchSize"
    }
)

# Microsoft Graph Authentication Function
# Implements OAuth2 client credentials flow for secure API access
function Get-GraphAuthToken {
    param (
        [Parameter(Mandatory=$true)][string]$tenantId,     # Organisation's Entra Directory ID
        [Parameter(Mandatory=$true)][string]$clientId,     # App Registration ID
        [Parameter(Mandatory=$true)][string]$clientSecret  # App Registration secret
    )

    # OAuth2 token request configuration
    $authBody = @{
        grant_type    = "client_credentials"
        client_id     = $clientId
        client_secret = $clientSecret
        scope         = "https://graph.microsoft.com/.default"  # Required scope for app permissions
    }

    try {
        # Request OAuth2 access token from Entra ID endpoint
        $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $authBody -ContentType 'application/x-www-form-urlencoded'
        return $response.access_token
    } catch {
        Write-Error "Microsoft Graph authentication failed: $_"
        throw
    }
}

# Query Result Count Function
# Determines total matching records before pagination
function Get-QueryCount {
    param (
        [Parameter(Mandatory=$true)][string]$query,      # Base KQL query
        [Parameter(Mandatory=$true)][string]$authToken   # Valid authentication token
    )

    # API request headers
    $headers = @{
        "Authorization" = "Bearer $authToken"
        "Content-Type"  = "application/json"
    }

    # M365D Advanced Hunting API endpoint
    $queryUri = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
    
    # Remove pagination operators for accurate count
    $baseQuery = $query -replace '\s*\|\s*order by.*$', ''
    $countQuery = "$baseQuery | summarize count()"
    
    # Prepare count query request
    $body = @{
        "query" = $countQuery
    } | ConvertTo-Json

    # Rate limit handling configuration
    $maxRetries = 3
    $retryCount = 0
    $success = $false

    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            $response = Invoke-RestMethod -Method Post -Uri $queryUri -Headers $headers -Body $body
            $success = $true
            return $response.results[0].count_
        } catch {
            if ($_.Exception.Response.StatusCode -eq 429) {
                # Handle rate limiting with exponential backoff
                $retryAfter = 12 # Default delay if header not present
                if ($_.Exception.Response.Headers["Retry-After"]) {
                    $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"]
                }
                Write-Host "Rate limit encountered during count. Waiting $retryAfter seconds..."
                Start-Sleep -Seconds $retryAfter
                $retryCount++
            } else {
                Write-Error "Count query failed: $_"
                return 0
            }
        }
    }

    if (-not $success) {
        Write-Error "Count query failed after maximum retries"
        return 0
    }
}

# Query Execution Function
# Retrieves paginated results with built-in retry logic
function Execute-GraphQuery {
    param (
        [Parameter(Mandatory=$true)][string]$query,      # KQL query to execute
        [Parameter(Mandatory=$true)][string]$authToken,  # Valid authentication token
        [Parameter(Mandatory=$false)][int]$skip = 0      # Pagination offset
    )

    # API request headers
    $headers = @{
        "Authorization" = "Bearer $authToken"
        "Content-Type"  = "application/json"
    }

    # M365D Advanced Hunting API endpoint
    $queryUri = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
    
    # Prepare query with pagination
    $cleanQuery = $query.Trim()
    $body = @{
        "query" = $cleanQuery
        "options" = @{
            "skip" = $skip
            "top" = $batchSize
        }
    } | ConvertTo-Json -Depth 10

    # Rate limit handling configuration
    $maxRetries = 3
    $retryCount = 0
    $success = $false

    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            # Execute paginated query
            $response = Invoke-RestMethod -Method Post -Uri $queryUri -Headers $headers -Body $body
            Write-Host "Successfully retrieved batch starting at offset $skip"
            $success = $true
            return $response.results
        } catch {
            if ($_.Exception.Response.StatusCode -eq 429) {
                # Handle rate limiting with exponential backoff
                $retryAfter = 12 # Default delay if header not present
                if ($_.Exception.Response.Headers["Retry-After"]) {
                    $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"]
                }
                Write-Host "Rate limit encountered. Waiting $retryAfter seconds..."
                Start-Sleep -Seconds $retryAfter
                $retryCount++
            } else {
                Write-Error "Query execution failed: $_"
                Write-Host "Failed query details: $cleanQuery"
                return @()
            }
        }
    }

    if (-not $success) {
        Write-Error "Query execution failed after maximum retries"
        return @()
    }
}

# Main Execution Block
try {
    Write-Host "Initiating Microsoft Graph authentication..."
    $authToken = Get-GraphAuthToken -tenantId $tenantId -clientId $clientId -clientSecret $clientSecret

    $outputEvents = @()       # Stores processed events pending transmission
    $processedEvents = @{}    # Tracks processed events to prevent duplicates

    # Process each configured query
    foreach ($query in $queries) {
        Write-Host "Processing query: $($query.Name)"
        
        # Get total record count for progress tracking
        $totalCount = Get-QueryCount -query $query.KQL -authToken $authToken
        Write-Host "Found $totalCount total records for $($query.Name)"
        
        if ($totalCount -eq 0) {
            Write-Host "No matching records for query: $($query.Name)"
            continue
        }

        # Process records in batches
        $skip = 0
        while ($skip -lt $totalCount) {
            # Implement rate limiting protection
            Start-Sleep -Seconds 2

            $data = Execute-GraphQuery -query $query.KQL -authToken $authToken -skip $skip

            if ($data -and $data.Count -gt 0) {
                Write-Host "Processing batch of $($data.Count) records from $($query.Name)"
                
                # Process individual events with deduplication
                $data | ForEach-Object { 
                    $eventKey = "$($query.Name)_$($_.Id)_$($_.TimeGenerated)"
                    
                    if (-not $processedEvents.ContainsKey($eventKey)) {
                        $processedEvents[$eventKey] = $true
                        $outputEvents += @{
                            QueryName = $query.Name
                            Data = $_
                            Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
                        }
                    }
                }
                $skip += $batchSize
            } else {
                break
            }
        }
    }

    # Forward collected events to Event Hub
    if ($outputEvents.Count -gt 0) {
        Write-Host "Forwarding $($outputEvents.Count) events to Event Hub..."

        # Use Azure Functions output binding for Event Hub transmission
        Push-OutputBinding -Name MDEEvents -Value $outputEvents

        Write-Host "Events successfully forwarded to Event Hub"
    } else {
        Write-Host "No events collected for transmission"
    }

} catch {
    # Handle and log any unhandled exceptions
    Write-Error "Script execution failed: $_"
}
