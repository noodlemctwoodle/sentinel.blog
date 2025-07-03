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

# Generate the file name
$tempFolder = $env:TEMP
$fileName = "IncidentReport.json"
$filePath = Join-Path -Path $tempFolder -ChildPath $fileName

# Initialize hashtable to store summary data at the very beginning of the script
$global:incidentSummaryByMonth = @{}

# Define subscription to client name mapping
$subscriptionToClientName = @{
    "<SUBSCRIPTION_ID_1>" = "Client_A"
    "<SUBSCRIPTION_ID_2>" = "Client_B"
    "<SUBSCRIPTION_ID_3>" = "Client_C"
    "<SUBSCRIPTION_ID_4>" = "Client_D"
}

function processWorkspace {
    param(
        [PSCustomObject]$Workspace, # Parameter to receive the workspace that will be processed
        [string]$ClientName # Parameter to receive the client name
    )

    Write-Host "Processing Workspace: $($Workspace.Name) for $ClientName" -ForegroundColor Green

    # Calculate the first and last day of the previous month in UTC
    $today = (Get-Date).ToUniversalTime()
    $firstDayOfThisMonth = (Get-Date -Year $today.Year -Month $today.Month -Day 1 -Hour 0 -Minute 0 -Second 0 -Millisecond 0).ToUniversalTime()
    $firstDayOfLastMonth = $firstDayOfThisMonth.AddMonths(-1)
    $lastDayOfLastMonth = $firstDayOfThisMonth.AddSeconds(-1)

    Write-Host "Date range for incidents: $firstDayOfLastMonth to $lastDayOfLastMonth" -ForegroundColor Green

    # Establish a connection with the Sentinel workspace
    $sentinelConnection = @{
        ResourceGroupName = $Workspace.ResourceGroupName
        WorkspaceName     = $Workspace.Name
    }

    # Fetch all Sentinel incidents from the last month
    $allIncidents = Get-AzSentinelIncident @sentinelConnection `
    | Where-Object { $_.CreatedTimeUTC -ge $firstDayOfLastMonth -and $_.CreatedTimeUTC -le $lastDayOfLastMonth } `
    | Select-Object -Property CreatedTimeUTC, Title, Severity, Status, Number, OwnerAssignedTo, @{Name='Workspace';Expression={$Workspace.Name}}, @{Name='ResourceGroup';Expression={$Workspace.ResourceGroupName}}, Resource 

    Write-Host "Fetched $($allIncidents.Count) incidents from Workspace: $($Workspace.Name)" -ForegroundColor Green 

    foreach ($incident in $allIncidents) {
        $incidentMonth = $lastDayOfLastMonth.ToString("MM-yyyy")
        $workspaceMonthKey = "$($Workspace.Name)-$incidentMonth"

        if (-not $global:incidentSummaryByMonth.ContainsKey($workspaceMonthKey)) {
            $global:incidentSummaryByMonth[$workspaceMonthKey] = 
            [PSCustomObject]@{
                Month            = $incidentMonth
                ClientName       = $ClientName
                TotalIncidents   = 0
                ClosedIncidents  = 0
                OpenIncidents    = 0
            }
        }

        $global:incidentSummaryByMonth[$workspaceMonthKey].TotalIncidents++
        if ($incident.Status -eq 'Closed') {
            $global:incidentSummaryByMonth[$workspaceMonthKey].ClosedIncidents++
        }
        $global:incidentSummaryByMonth[$workspaceMonthKey].OpenIncidents = $global:incidentSummaryByMonth[$workspaceMonthKey].TotalIncidents - $global:incidentSummaryByMonth[$workspaceMonthKey].ClosedIncidents
    }

    # Display the summarized count
    $incidentSummaryByMonth.Values | Format-Table -AutoSize
}

# Process each Azure subscription
foreach ($subscriptionId in $subscriptionToClientName.Keys) {
    $clientName = $subscriptionToClientName[$subscriptionId]
    Write-Host "Processing Subscription: $subscriptionId for $clientName" -ForegroundColor Green

    # Retrieve the secret value from Key Vault
    $secret = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $secretName -AsPlainText)
    if ([string]::IsNullOrEmpty($secret)) {
        Write-Host "Secret value is null or empty."
    }

    # Authenticate with Azure AD App Registration
    $securePassword = ConvertTo-SecureString $secret -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential($appId, $securePassword)

    # Connect to the subscription
    Connect-AzAccount -Credential $creds -Tenant $TenantId -Subscription $subscriptionId -ServicePrincipal -WarningAction SilentlyContinue

    $workspaces = Get-AzOperationalInsightsWorkspace -WarningAction SilentlyContinue
    Write-Host "Retrieved Workspaces for Subscription: $subscriptionId" -ForegroundColor Green

    $sentinelWs = $workspaces | Where-Object {
        (Get-AzOperationalInsightsIntelligencePacks -WarningAction SilentlyContinue -ResourceGroupName $_.ResourceGroupName -WorkspaceName $_.Name).Where({$_.Name -eq "SecurityInsights" -and $_.Enabled -eq $true})
    }

    if($sentinelWs -is [System.Collections.ICollection]) {
        foreach ($workspace in $sentinelWs) {
            processWorkspace -Workspace $workspace -ClientName $clientName
        }
    } else {
        processWorkspace -Workspace $sentinelWs -ClientName $clientName
    }
}

# Flatten the list of incidents per month into a single list for export
$finalOutput = foreach ($workspaceMonthKey in $global:incidentSummaryByMonth.Keys) {
    $summary = $global:incidentSummaryByMonth[$workspaceMonthKey]

    [PSCustomObject]@{
        Month           = $summary.Month
        ClientName      = $summary.ClientName
        LoggedIncidents = $summary.TotalIncidents
        ClosedIncidents = $summary.ClosedIncidents
        OpenIncidents   = $summary.OpenIncidents
    }
}

# Sort the final output by ClientName alphabetically and check for data
$sortedFinalOutput = $finalOutput | Sort-Object ClientName
if (-not $sortedFinalOutput) {
    Write-Host "No data to write to the file."
    return
}

# Convert the sorted final output to JSON and save to file
$sortedFinalOutput | ConvertTo-Json | Out-File -FilePath $filePath -Force
Write-Host "Data written to file: $filePath"

# Connect to Azure Key Vault and get the storage account key
$storageAccountKey = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $storageSecretName -AsPlainText)

# Create a storage context
$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey

# Upload the file to Azure Blob Storage
try {
    Set-AzStorageBlobContent -File $filePath -Container $containerName -Blob $fileName -Context $context -Force
    Write-Host "File uploaded to blob storage: $fileName"
} catch {
    Write-Host "Error uploading file: $_"
}

# Additional logging to confirm script completion
Write-Host "Script execution completed"