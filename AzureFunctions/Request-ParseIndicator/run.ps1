using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Interact with query parameters or the body of the request.
$indicator = $Request.Body.indicatorValue

# Define patterns in a hashtable for better structure
$patterns = @{
    FileMd5               = '^[a-fA-F0-9]{32}$'
    FileSha1              = '^[a-fA-F0-9]{40}$'
    FileSha256            = '^[a-fA-F0-9]{64}$'
    CertificateThumbprint = '^[a-fA-F0-9]{40}$'
    IpAddress             = '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$|^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$'
    DomainName            = '^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
}

$result = "Invalid Indicator Value. No action taken."

# Use foreach loop to go over each pattern in the hashtable
foreach ($key in $patterns.Keys) {
    if ($indicator -match $patterns[$key]) {
        $result = $key
        break
    }
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = @{
            indicatorValue = $result
            Original       = $request.body.indicatorValue
        }
    })