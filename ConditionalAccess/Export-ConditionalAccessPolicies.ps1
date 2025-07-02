<#
.SYNOPSIS
 This script will export all conditional access policies and named locations

.DESCRIPTION
 This script will export all conditional access policies and named locations

.PARAMETER clientId
 Enter the client ID of the AAD App Registration

.PARAMETER clientSecret
 Enter the client Secret of the AAD App Registration

.PARAMETER tenantId
 Enter the tenant id

.PARAMETER outputPath
 Enter the location to store the .JSON files eg "C:\Temp\Policies"

.EXAMPLE
.\Export-ConditionalAccessPolicies.ps1 -clientId <String> -clientSecret <string> -tenantId <String> -outputPath <String>

.NOTES
 Version:        0.1
 Author:         noodlemctwoodle
 Creation Date:  16/02/2022
#>

param(
  [Parameter(mandatory = $true)]
  [String]$clientId,
  [Parameter(mandatory = $true)]
  [String]$clientSecret,
  [Parameter(mandatory = $true)]
  [String]$tenantId,
  [Parameter(mandatory = $true)]
  [String]$outputPath
)

# Connect to Graph

$Body = @{    
Grant_Type    = "client_credentials"
resource      = "https://graph.microsoft.com"
client_id     = $clientId
client_secret = $clientSecret
} 

$ConnectGraph = Invoke-RestMethod -Uri "https://login.microsoft.com/$tenantId/oauth2/token?api-version=1.0" -Method POST -Body $Body 

# Variable Collections

$HeaderParams = @{
  'Content-Type'  = "application\json"
  'Authorization' = "Bearer $($ConnectGraph.access_token)"
}

# Conditional Access policies
$conditionalAccessPoliciesRequest = (Invoke-RestMethod -Headers $HeaderParams -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Method Get)
$conditionalAccessPolicies = $conditionalAccessPoliciesRequest.value

# Named locations
$namedLocationsRequest = (Invoke-RestMethod -Headers $HeaderParams -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -Method Get)
$namedLocations = $namedLocationsRequest.value

# Export to JSON

try{
  foreach($policy in $conditionalAccessPolicies){
    $filePath = "$($outputPath)\Policy - $($policy.displayName).json"
    $policy | convertto-json -Depth 10 | out-file $filePath
    $Clean = Get-Content $filePath | Select-String -Pattern '"id":', '"createdDateTime":', '"modifiedDateTime":' -notmatch
    $Clean | Out-File -FilePath $filePath
    write-host "Exported policy: $($policy.displayName)" -ForegroundColor green
  }  
}
catch{
  write-host "Error: $($_.Exception.Message)" -ForegroundColor red
}

try{
  foreach($namedLocation in $namedLocations){
      $filePath = "$($outputPath)\Location - $($namedLocation.displayName).json"
      $namedLocation | convertto-json -Depth 10 | out-file $filePath
      $Clean = Get-Content $filePath | Select-String -Pattern '"id":', '"createdDateTime":', '"modifiedDateTime":' -notmatch
      $Clean | Out-File -FilePath $filePath
      write-host "Exported location: $($namedLocation.displayName)" -ForegroundColor green
  }
}
catch{
  write-host "Error: $($_.Exception.Message)" -ForegroundColor red
}