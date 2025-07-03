# Import the System.Net namespace for HTTP functionality
using namespace System.Net

# Define parameters passed in via the param block for Azure Functions HTTP trigger
param($Request, $TriggerMetadata)

# Extract 'name' from the Request parameters, if not available, retrieve it from the Request body
$name = $Request.Query.Name
if (-not $name) {
    $name = $Request.Body.Name
}

# Extract 'date' from the Request parameters, if not available, retrieve it from the Request body
$date = $Request.Query.Date
if (-not $date) {
    $date = $Request.Body.Date
}

# Extract 'api' from the Request parameters, if not available, retrieve it from the Request body
$api = $Request.Query.API
if (-not $api) {
    $api = $Request.Body.API
}

# Azure Key Vault configuration
$vaultName = '<YOUR_KEYVAULT_NAME>'

# NIST API Key configuration
$NISTsecretName = '<YOUR_NIST_SECRET_NAME>'
$apiKey = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $NISTsecretName -AsPlainText)

# OpenCVE API credentials configuration
$username = '<YOUR_OPENCVE_USERNAME>'
$openCVEsecretName = '<YOUR_OPENCVE_SECRET_NAME>'
$openCVEsecret = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $openCVEsecretName -AsPlainText)
$credential = New-Object System.Management.Automation.PSCredential($username, (ConvertTo-SecureString $openCVEsecret -AsPlainText -Force))

# Function to retrieve vulnerability data from Microsoft Security Response Center API
function Get-MSVulnerability {
    param (
        $date,  # Security bulletin date/alias
        $name   # CVE identifier
    )
    
    # If no date provided, get it from Microsoft API using the CVE name
    if (-not $date) {
        # Retrieve 'date' from the Microsoft API using 'name'
        $aliasResponse = Invoke-RestMethod -Uri ("https://api.msrc.microsoft.com/cvrf/v2.0/Updates('" + $name + "')")
        if ($aliasResponse -and $aliasResponse.value -and $aliasResponse.value.Count -gt 0) {
            $date = $aliasResponse.value[0].Alias
        }
        else {
            Write-Error "Alias not found in the API response"
            return
        }
    }

    # Send a GET request to the Microsoft API to get the CVE details
    $response = (Invoke-WebRequest ("https://api.msrc.microsoft.com/cvrf/" + $date) -Headers @{Accept = "application/json" }).Content | ConvertFrom-Json -Depth 99

    # Filter out the specific vulnerability details we want from the response
    $CVE = $response.Vulnerability | Where-Object CVE -EQ $name

    # Split exploitability details into an array of key-value pairs
    $Exploitability = $CVE.Threats | Where-Object Type -EQ 1 | ForEach-Object {
        $exploitDetails = $_.description.value -split ";"
        $exploitHashTable = @{}
        foreach ($detail in $exploitDetails) {
            $keyValue = $detail -split ":", 2
            if ($keyValue.Count -eq 2) {
                $exploitHashTable[$keyValue[0].Trim()] = $keyValue[1].Trim()
            }
        }
        $exploitHashTable
    }

    # Create a custom object to represent the CVE data we're interested in
    $MSVulnerabilityObject = [PSCustomObject]@{
        CVE            = $CVE.CVE
        Title          = $CVE.Title.Value
        Description    = ($CVE.Notes.Value -replace "<.*?>", "" -split "\\n" | ForEach-Object { $_.Trim() }) -join "`r`n"
        CVSSBaseScore  = ($CVE.CVSSScoreSets | Group-Object -Property BaseScore -NoElement).Name
        Exploitability = $Exploitability
        Mitigations    = ($CVE.Remediations | Where-Object type -EQ 1).description.value -replace "<.*?>", "" -replace "\\n", "`r`n"
        Revisions      = $CVE.RevisionHistory
        Impact         = ($CVE.Threats.Description.Value | Select-Object -Unique | Where-Object { $_ -ne "Important" -and $_ -notlike "*;*" })
    }

    return $MSVulnerabilityObject
}

# Function to retrieve vulnerability data from NIST National Vulnerability Database
function Get-NISTVulnerability {
    param(
        [Parameter(Mandatory = $true)]
        [string]$name,    # CVE identifier

        [Parameter(Mandatory = $true)]
        [string]$apiKey   # NIST API key for authentication
    )

    # Function to convert properties to individual keys for easier processing
    function ConvertPropertiesToIndividualKeys($metrics) {
        $result = @{}
        if ($null -ne $metrics) {
            $metrics.PSObject.Properties | ForEach-Object {
                if ($null -ne $_) {
                    $result[$_.Name] = $_.Value
                }
            }
        }
        return $result
    }

    # Make request to the NIST API with error handling
    try {
        $nist = (Invoke-WebRequest -Uri "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$name" -Headers @{Accept = "application/json"; 'X-Api-Key'=$apiKey} -ErrorAction Stop).Content | ConvertFrom-Json -Depth 99
    }
    catch {
        Write-Error "Failed to fetch data from NIST API: $_"
        return $null
    }

    # If no results found, return null
    if ($nist.totalResults -eq 0) {
        return $null
    }

    # Process data from the NIST API response
    $vulnerability = $null
    if ($nist.vulnerabilities.Count -gt 0) {
        $vulnerability = $nist.vulnerabilities | Select-Object -First 1
    }

    if ($null -eq $vulnerability) {
        Write-Warning "No vulnerabilities found for $name"
        return $null
    }

    # Extract CVSS v2 metrics and properties
    $metricsV2 = $vulnerability.cve.metrics.cvssMetricV2 | Select-Object -First 1
    $metricsV2Properties = ConvertPropertiesToIndividualKeys ($metricsV2 | Select-Object -ExpandProperty cvssData)

    # List of additional properties to include from CVSS v2
    $additionalProperties = @("baseSeverity", "exploitabilityScore", "impactScore", "acInsufInfo", "obtainAllPrivilege", "obtainUserPrivilege", "obtainOtherPrivilege", "userInteractionRequired")

    # Add the additional properties to the $metricsV2Properties
    foreach ($property in $additionalProperties) {
        $metricsV2Properties.$property = $metricsV2.$property
    }

    # Extract CVSS v3.1 metrics
    $metricsV31Properties = ConvertPropertiesToIndividualKeys ($vulnerability.cve.metrics.cvssMetricV31 | Select-Object -First 1 -ExpandProperty cvssData)

    # Process URLs and tags from references
    $urls = @()
    $tags = @()
    foreach ($reference in $vulnerability.cve.references) {
        $urls += $reference.url
        $tags += $reference.tags
    }
    $urls = $urls | Sort-Object | Get-Unique
    $tags = $tags | Sort-Object | Get-Unique

    # Create a custom object with processed NIST vulnerability data
    $NISTVulnerabilityObject = [PSCustomObject]@{
        id                      = $vulnerability.cve.id
        sourceIdentifier        = $vulnerability.cve.sourceIdentifier
        published               = $vulnerability.cve.published
        lastModified            = $vulnerability.cve.lastModified
        vulnStatus              = $vulnerability.cve.vulnStatus
        referenceTags           = $tags -join ", "
        descriptions            = ($vulnerability.cve.descriptions | Where-Object { $_.lang -eq 'en' })[0].value
        configurations          = $vulnerability.cve.configurations[0].nodes -join ", "
        weaknesses              = ($vulnerability.cve.weaknesses | ForEach-Object { $_.description | Where-Object { $_.lang -eq 'en' } | ForEach-Object { $_.value } }) -join ", "
        cvssMetricV2 = @{
            accessVector            = $metricsV2Properties.accessVector
            accessComplexity        = $metricsV2Properties.accessComplexity
            authentication          = $metricsV2Properties.authentication
            impactScore             = $metricsV2Properties.impactScore
            exploitabilityScore     = $metricsV2Properties.exploitabilityScore
            baseSeverity            = $metricsV2Properties.baseSeverity
            acInsufInfoV2           = $metricsV2Properties.acInsufInfo
            obtainAllPrivilege      = $metricsV2Properties.obtainAllPrivilege
            obtainUserPrivilege     = $metricsV2Properties.obtainUserPrivilege
            obtainOtherPrivilege    = $metricsV2Properties.obtainOtherPrivilege
            userInteractionRequired = $metricsV2Properties.userInteractionRequired
            scope                   = $metricsV31Properties.scope
        }
        cvssMetricV31 = @{
            baseScore               = $metricsV31Properties.baseScore
            baseSeverity            = $metricsV31Properties.baseSeverity
            attackVector            = $metricsV31Properties.attackVector
            attackComplexity        = $metricsV31Properties.attackComplexity
            privilegesRequired      = $metricsV31Properties.privilegesRequired
            userInteraction         = $metricsV31Properties.userInteraction
            integrityImpact         = $metricsV31Properties.integrityImpact
            availabilityImpact      = $metricsV31Properties.availabilityImpact
            confidentialityImpact   = $metricsV31Properties.confidentialityImpact
            vectorString            = $metricsV31Properties.vectorString
        }  
        referenceUrls           = $urls
    }
    return $NISTVulnerabilityObject
}

# Function to retrieve vulnerability data from OpenCVE API
function Get-OpenCVEVulnerability {
    param(
        [Parameter(Mandatory = $true)]
        [string]$name,        # CVE identifier

        [Parameter(Mandatory = $true)]
        [PSCredential]$credential  # OpenCVE API credentials
    )

    # Make request to the OpenCVE API with authentication
    $opencve = (Invoke-WebRequest -Uri "https://www.opencve.io/api/cve/$name" -Headers @{Accept = "application/json"} -Credential $credential).Content | ConvertFrom-Json -Depth 99

    # Process data from the OpenCVE API response
    $vulnerability = $opencve

    # Process vendors data into a more readable format and convert it into an array
    $vendors = $vulnerability.vendors.PSObject.Properties | ForEach-Object {
        $_.Value -replace '_', ' '
    } | ForEach-Object { $_.Split(',') } | ForEach-Object { $_.Trim() }

    # Extract and deduplicate reference data
    $reference_data = $vulnerability.raw_nvd_data.cve.references.reference_data | Group-Object -Property url -AsHashTable -AsString
    $tags = $reference_data.Values | ForEach-Object { $_.tags } | Select-Object -Unique

    # Extract baseMetricV3 and cvssV3 data
    $baseMetricV3 = $vulnerability.raw_nvd_data.impact.baseMetricV3
    $cvssV3 = $baseMetricV3.cvssV3 | ConvertTo-Json -Depth 99 | ConvertFrom-Json

    # Create a custom object with processed OpenCVE vulnerability data
    $OpenCVEVulnerabilityObject = [PSCustomObject]@{
        id                 = $vulnerability.id
        summary            = $vulnerability.summary
        created_at         = $vulnerability.created_at
        updated_at         = $vulnerability.updated_at
        cvss_v2            = $vulnerability.cvss.v2
        cvss_v3            = $vulnerability.cvss.v3
        vendors            = $vendors
        cwes               = $vulnerability.cwes -join ", "
        reference_urls     = $reference_data.Keys
        reference_tags     = $tags
        baseMetricV3       = @{
            impactScore           = $baseMetricV3.impactScore
            exploitabilityScore   = $baseMetricV3.exploitabilityScore
        }
        cvssV3             = @{
            scope                 = $cvssV3.scope
            version               = $cvssV3.version
            baseScore             = $cvssV3.baseScore
            attackVector          = $cvssV3.attackVector
            baseSeverity          = $cvssV3.baseSeverity
            vectorString          = $cvssV3.vectorString
            integrityImpact       = $cvssV3.integrityImpact
            userInteraction       = $cvssV3.userInteraction
            attackComplexity      = $cvssV3.attackComplexity
            availabilityImpact    = $cvssV3.availabilityImpact
            privilegesRequired    = $cvssV3.privilegesRequired
            confidentialityImpact = $cvssV3.confidentialityImpact
        }
    }

    return $OpenCVEVulnerabilityObject
}

# Main logic: Route to appropriate API based on the 'api' parameter
if ($api -eq 'MS') {
    # Call Microsoft Security Response Center API
    $vulnerabilityObject = Get-MSVulnerability -name $name -date $date
}
elseif ($api -eq 'NIST') {
    # Call NIST National Vulnerability Database API
    $vulnerabilityObject = Get-NISTVulnerability -name $name -apiKey $apiKey
}
elseif ($api -eq 'OPENCVE') {
    # Call OpenCVE API
    $vulnerabilityObject= Get-OpenCVEVulnerability -name $name -credential $credential
}
else {
    # Return error for invalid API specification
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = "Invalid API specified. Please specify 'MS', 'NIST', or 'OPENCVE'"
        })
    return
}

# Convert CVE data to JSON for output, or provide appropriate error messages if data is not available
if ($vulnerabilityObject) {
    # Successfully retrieved vulnerability data - convert to JSON
    $body = ConvertTo-Json -InputObject $vulnerabilityObject -Depth 99
}
elseif (-not $vulnerabilityObject) {
    # No vulnerability data found for the provided CVE
    $body = "CVE not found"
}
else {
    # No valid CVE provided in the request
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::NoContent
            Body       = "No valid CVE provided"
        })
}

# Pass the final response to the output bindings with HTTP 200 OK status
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body       = $body
    })