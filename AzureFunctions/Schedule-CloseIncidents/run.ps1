# Input bindings are passed in via param block.
param($Timer)

# Initialize the owner details.
$ownerName = "Notification UPN"
$ownerEmail = "sentinelnotifications@tld.com"

# Define your Azure AD App Registration details
$tenantId = '<TenantId>'

# Application (client) ID
$appId = '<ApplicationId>'

# Define your Key Vault and Secret Name
$vaultName = '<KeyVaultName>'
$secretName = '<KeyVaultSecretName>'

# Get all subscriptions
$Subscriptions = @(
    "b7bd67e6-73ee-42c6-9922-547a3da4e98a", # "Customer1"
    "b7bd67e6-73ee-42c6-9922-547a3da4e98a", # "Customer2"
    "b7bd67e6-73ee-42c6-9922-547a3da4e98a", # "Customer3"
    "b7bd67e6-73ee-42c6-9922-547a3da4e98a" # "Customer4"
)

# Initialize the incident classification.
$incidentClassification = @{
    Undetermined = "Undetermined"
}

# Set the closure comment.
$closureComment = "Azure Function - The workspace has a retention policy of 90 days. This incident was raised over 100 days ago, due to the age of this incident it has bveen automatiocally closed."

# Loop through each subscription
foreach ($subscription in $subscriptions) {

    Write-Host "Processing subscription: $subscription"
    
    # Retrieve the secret value from Key Vault
    $secret = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $secretName -AsPlainText)

    # Authenticate with Azure AD App Registration
    $creds = New-Object System.Management.Automation.PSCredential($appId, (ConvertTo-SecureString $secret -AsPlainText -Force))

    # Connect to the subscription
    Connect-AzAccount -Credential $creds -Tenant $TenantId -Subscription $subscription -ServicePrincipal
    
    # Get all Log Analytics workspaces
    $workspaces = Get-AzOperationalInsightsWorkspace
    
    Write-Host "Found $(($workspaces).count) workspaces" -ForegroundColor Green
    
    # Iterate over each workspace
    foreach ($workspace in $workspaces) {
    
        Write-Host "Processing workspace: $($workspace.Name)"
    
        # Define the sentinel connection for each workspace
        $sentinelConnections = @{
            ResourceGroupName = $workspace.ResourceGroupName
            WorkspaceName     = $workspace.Name
        }
    
        # Iterate over each Sentinel workspace to process it.
        foreach ($sentinelConnection in $sentinelConnections) {
            Write-Host "Processing sentinel connection: $($sentinelConnection)"
    
             # Set the incident age as 100 days prior to the current date.
            $incidentAge = (Get-Date).AddDays(-100)
    
            # Retrieve the incidents from Sentinel which are not closed and created more than 90 days ago. Select required properties and sort them in descending order based on creation time.
            $Incidents = Get-AzSentinelIncident @SentinelConnection | 
            Where-Object { $_.Status -ne "Closed" -and $_.CreatedTimeUTC -lt $IncidentAge } | 
            Select-Object -property CreatedTimeUTC, Title, Number, OwnerAssignedTo, Severity, Status, Name | 
            Sort-Object -Property CreatedTimeUTC -Descending
    
            Write-Host "Found $(($Incidents).count) incidents" -ForegroundColor Magenta

            # Display the created time and status of the first incident found.
            $firstIncident = $Incidents | Select-Object -First 1
            Write-Host "First Incident: CreatedTimeUTC - $($firstIncident.CreatedTimeUTC), Status - $($firstIncident.Status)"

            # Display the created time and status of the last incident found.
            $lastIncident = $Incidents | Select-Object -Last 1
            Write-Host "Last Incident: CreatedTimeUTC - $($lastIncident.CreatedTimeUTC), Status - $($lastIncident.Status)"

            # Wait for 20 seconds before updating the incident.
            #Start-Sleep -Seconds 15

            # Iterate through each incident, update its details, set its status to 'Closed', assign owner, set the classification, and set the closure comment.
            $Incidents | ForEach-Object {
                Write-Host "Updating incident: $($_.Name) with title: $($_.Title)"
                $incident = Update-AzSentinelIncident @SentinelConnection `
                    -Id $_.Name `
                    -Title $_.Title `
                    -Severity $_.Severity `
                    -Status Closed `
                    -OwnerAssignedTo $OwnerName `
                    -OwnerUserPrincipalName $OwnerEmail `
                    -Classification ($IncidentClassification.GetEnumerator() | Select-Object -First 1).Key `
                    -ClassificationComment $ClosureComment `
                    -Confirm:$false

                # Check if the incident update was successful.    
                if ($incident) {
                    Write-Host "Successfully updated incident: $($incident.Name)" -ForegroundColor Green
                } else {
                    Write-Host "Failed to update incident: $($_.Name)" -ForegroundColor Red
                }
                
                # Display key properties of the updated incident.
                $incident | Select-Object Title, CreatedTimeUtc, Severity, Number
            }

            Write-Host "Updated $(($Incidents).count) incidents" -ForegroundColor Green
        }
    }
}