param ([Parameter(Mandatory=$true)] $Log, $Type="file", $Output, $DcrImmutableId, $DceURI, $Table)
################
##### Usage
################
# LogGenerator.ps1
#   -Log <String>              - Log file to be forwarded
#   [-Type "file|API"]         - Whether the script should generate sample JSON file or send data via
#                                API call. Data will be written to a file by default.
#   [-Output <String>]         - Path to resulting JSON sample
#   [-DcrImmutableId <string>] - DCR immutable ID
#   [-DceURI]                  - Data collection endpoint URI
#   [-Table]                   - The name of the custom log table, including "_CL" suffix


##### >>>> PUT YOUR VALUES HERE <<<<<
# Information needed to authenticate to Azure Active Directory and obtain a bearer token
$tenantId = "<Azure Tenant ID>"; #the tenant ID in which the Data Collection Endpoint resides
$appId = "<App Registration Client ID>"; #the app ID created and granted permissions
$appSecret = "<App Registration Secret>"; #the secret created for the above app - never store your secrets in the source code
##### >>>> END <<<<<


$file_data = Get-Content $Log
if ("file" -eq $Type) {
    ############
    ## Convert plain log to JSON format and output to .json file
    ############
    # If not provided, get output file name
    if ($null -eq $Output) {
        $Output = Read-Host "Enter output file name" 
    };

    # Form file payload
    $payload = @();
    $records_to_generate = [math]::min($file_data.count, 500)
    for ($i=0; $i -lt $records_to_generate; $i++) {
        $log_entry = @{
            # Define the structure of log entry, as it will be sent
            Time = Get-Date ([datetime]::UtcNow) -Format O
            Application = "LogGenerator"
            RawData = $file_data[$i]
        }
        $payload += $log_entry
    }
    # Write resulting payload to file
    New-Item -Path $Output -ItemType "file" -Value ($payload | ConvertTo-Json) -Force

} else {
    ############
    ## Send the content to the data collection endpoint
    ############
    if ($null -eq $DcrImmutableId) {
        $DcrImmutableId = Read-Host "Enter DCR Immutable ID" 
    };

    if ($null -eq $DceURI) {
        $DceURI = Read-Host "Enter data collection endpoint URI" 
    }

    if ($null -eq $Table) {
        $Table = Read-Host "Enter the name of custom log table" 
    }

    ## Obtain a bearer token used to authenticate against the data collection endpoint
    $scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
    $body = "client_id=$appId&scope=$scope&client_secret=$appSecret&grant_type=client_credentials";
    $headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
    $uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    $bearerToken = (Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers).access_token

    ## Generate and send some data
    foreach ($line in $file_data) {
        # We are going to send log entries one by one with a small delay
        $log_entry = @{
            # Define the structure of log entry, as it will be sent
            Time = Get-Date ([datetime]::UtcNow) -Format O
            Application = "LogGenerator"
            RawData = $line
        }
        # Sending the data to Log Analytics via the DCR!
        $body = $log_entry | ConvertTo-Json -AsArray;
        $headers = @{"Authorization" = "Bearer $bearerToken"; "Content-Type" = "application/json" };
        $uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/Custom-$Table"+"?api-version=2021-11-01-preview";
        $uploadResponse = Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers;

        # Let's see how the response looks
        Write-Output $uploadResponse
        Write-Output "---------------------"

        # Pausing for 1 second before processing the next entry
        Start-Sleep -Seconds 1
    }
}