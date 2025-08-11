<#
.SYNOPSIS
    Microsoft Defender XDR Custom Detection Rules Manager
    Exports, imports, and manages custom detection rules via Microsoft Graph API

.DESCRIPTION
    This script provides functionality to export and import Microsoft Defender XDR custom detection rules
    including their entity mappings (impacted assets and related evidence). It uses the Microsoft Graph API
    to retrieve and create detection rules, preserving all configurations including KQL queries, schedules,
    severity levels, MITRE techniques, and entity mappings.

.PARAMETER TenantId
    The Entra ID Tenant ID where the Defender XDR instance is hosted
    Example: "12345678-1234-1234-1234-123456789012"

.PARAMETER ClientId
    The Application (Client) ID of the Entra ID App Registration
    The app must have appropriate Graph API permissions

.PARAMETER ClientSecret
    The client secret for the Entra ID App Registration
    This will be prompted securely if not provided

.PARAMETER Action
    The operation to perform. Valid values:
    - Export: Exports custom detection rules to JSON file(s)
    - Import: Imports custom detection rules from JSON file
    - List: Lists all custom detection rules in the tenant

.PARAMETER OutputPath
    Path where the exported JSON file will be saved
    Default: ".\DefenderCustomDetections_[timestamp].json"
    When using -Single, this becomes the folder path

.PARAMETER ImportPath
    Path to the JSON file containing rules to import
    Required when Action is "Import"

.PARAMETER IncludeDisabled
    Switch to include disabled rules in the export or list operation
    By default, only enabled rules are processed

.PARAMETER Single
    Switch to export each rule as a separate JSON file instead of a single file
    Files will be saved in a folder with timestamp

.EXAMPLE
    .\Export-XDRCustomDetections.ps1 -Action Export -TenantId "abc-123" -ClientId "def-456" -ClientSecret "secret123"
    
    Exports all enabled custom detection rules to a single timestamped JSON file

.EXAMPLE
    .\Export-XDRCustomDetections.ps1 -Action Export -Single
    
    Exports each custom detection rule to individual JSON files in a timestamped folder

.EXAMPLE
    .\Export-XDRCustomDetections.ps1 -Action Import -ImportPath ".\backup.json" -TenantId "abc-123" -ClientId "def-456"
    
    Imports custom detection rules from backup.json file

.EXAMPLE
    .\Export-XDRCustomDetections.ps1 -Action List
    
    Lists all custom detection rules in the tenant (will prompt for credentials)

.NOTES
    Version:        1.1.0
    Author:         TobyG
    Creation Date:  August 11, 2025
    Last Modified:  August 11, 2025
    
    Prerequisites:
    - Entra ID App Registration with the following Microsoft Graph API permission:
        * CustomDetection.ReadWrite.All (Application) - Read and write all custom detection rules
    - Admin consent must be granted for the app permission
    
    Required Roles (for user authentication):
    - Security Admin OR
    - Security Operator (also needs the manage security setting role in Unified RBAC if turned on) OR
    - Unified RBAC Security Settings Manager

.LINK
    https://learn.microsoft.com/en-us/graph/api/security-detectionrule-list
    https://learn.microsoft.com/en-us/graph/api/security-detectionrule-post-detectionrules
    https://learn.microsoft.com/en-us/graph/api/security-detectionrule-get
    https://learn.microsoft.com/en-us/graph/api/security-detectionrule-delete
    https://www.infernux.no/DefenderXDR-CustomDetectionRules/

.FUNCTIONALITY
    - Export custom detection rules with complete configuration
    - Export as single file or individual files per rule
    - Import detection rules to same or different tenant
    - Preserve entity mappings (impacted assets and related evidence)
    - Maintain KQL queries, schedules, and alert templates
    - Handle duplicate detection during import
    - Support for MITRE ATT&CK techniques mapping
    - Batch processing of multiple rules

.COMPONENT
    Microsoft Graph API
    Microsoft Defender XDR
    Microsoft Entra ID

.ROLE
    Security Administrator
    Security Operator
    Unified RBAC Security Settings Manager

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientSecret,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\DefenderCustomDetections",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Export", "Import", "List")]
    [string]$Action = "Export",
    
    [Parameter(Mandatory=$false)]
    [string]$ImportPath,
    
    [switch]$IncludeDisabled,
    
    [switch]$Single
)

# Script version
$ScriptVersion = "1.1.0"
Write-Host "`n=== Microsoft Defender XDR Custom Detections Manager v$ScriptVersion ===" -ForegroundColor Cyan

# Authenticate to Microsoft Graph API and retrieve access token
function Get-AccessToken {
    param( 
        [Parameter(Mandatory = $true)]
        [string]$tenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$clientId,
        
        [Parameter(Mandatory = $true)]
        [string]$clientSecret
    )
    
    $graphResource = 'https://graph.microsoft.com/'
    $oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"
    
    $authBody = [Ordered]@{
        resource      = $graphResource
        client_id     = $clientId
        client_secret = $clientSecret
        grant_type    = 'client_credentials'
    }
    
    Write-Host "[*] Authenticating to Graph API..." -ForegroundColor Yellow
    
    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
        Write-Host "[✓] Authentication successful" -ForegroundColor Green
        return $authResponse.access_token
    } catch {
        Write-Host "[!] Authentication failed: $_" -ForegroundColor Red
        exit 1
    }
}

# Retrieve all custom detection rules from Microsoft Defender XDR
function Get-DetectionRules {
    param(
        [string]$Token,
        [bool]$IncludeDisabled = $false
    )
    
    $headers = @{
        'Authorization' = "Bearer $Token"
        'Content-Type' = 'application/json'
    }
    
    $uri = "https://graph.microsoft.com/beta/security/rules/detectionRules"
    
    Write-Host "[*] Fetching detection rules..." -ForegroundColor Yellow
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -ErrorAction Stop
        
        if ($response.value) {
            # Filter for custom rules only (exclude system rules)
            $customRules = $response.value | Where-Object { -not $_.isSystemRule }
            
            if (-not $IncludeDisabled) {
                $customRules = $customRules | Where-Object { $_.isEnabled -ne $false }
            }
            
            Write-Host "[✓] Found $($customRules.Count) custom detection rule(s)" -ForegroundColor Green
            
            # Retrieve detailed information for each rule
            $detailedRules = @()
            foreach ($rule in $customRules) {
                Write-Host "    Getting details for: $($rule.displayName)" -ForegroundColor Gray
                $details = Get-DetectionRuleById -Token $Token -RuleId $rule.id
                if ($details) {
                    $detailedRules += $details
                } else {
                    $detailedRules += $rule
                }
            }
            
            return $detailedRules
        }
        
        return @()
    } catch {
        Write-Host "[!] Error: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Retrieve specific detection rule details by ID
function Get-DetectionRuleById {
    param(
        [string]$Token,
        [string]$RuleId
    )
    
    $headers = @{
        'Authorization' = "Bearer $Token"
        'Content-Type' = 'application/json'
    }
    
    $uri = "https://graph.microsoft.com/beta/security/rules/detectionRules/$RuleId"
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -ErrorAction Stop
        return $response
    } catch {
        return $null
    }
}

# Create a new detection rule in Microsoft Defender XDR
function New-DetectionRule {
    param (
        [Parameter(Mandatory = $true)]
        [string]$displayName,
        
        [Parameter(Mandatory = $true)]
        [bool]$isEnabled,
        
        [Parameter(Mandatory = $true)]
        [string]$queryText,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("0","1H", "3H", "12H", "24H")]
        [string]$period,
        
        [Parameter(Mandatory = $false)]
        [string]$alertTitle,
        
        [Parameter(Mandatory = $false)]
        [string]$alertDescription,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("informational", "low", "medium", "high")]
        [string]$severity,
        
        [Parameter(Mandatory = $false)]
        [string]$category,
        
        [Parameter(Mandatory = $false)]
        [object]$impactedAssets,
        
        [Parameter(Mandatory = $false)]
        [object]$relatedEvidence,
        
        [string[]]$mitreTechniques = @(),
        
        [Parameter(Mandatory = $false)]
        [string]$token
    )
    
    $body = @{
        displayName = $displayName
        isEnabled = $isEnabled
        queryCondition = @{
            queryText = $queryText
        }
        schedule = @{
            period = $period
        }
    }
    
    # Configure detection action and alert template if parameters are provided
    if ($alertTitle -or $alertDescription -or $severity -or $category -or $impactedAssets -or $relatedEvidence) {
        $body.detectionAction = @{
            alertTemplate = @{}
            organizationalScope = $null
            responseActions = @()
        }
        
        if ($alertTitle) { $body.detectionAction.alertTemplate.title = $alertTitle }
        if ($alertDescription) { $body.detectionAction.alertTemplate.description = $alertDescription }
        if ($severity) { $body.detectionAction.alertTemplate.severity = $severity.ToLower() }
        if ($category) { $body.detectionAction.alertTemplate.category = $category }
        if ($mitreTechniques) { $body.detectionAction.alertTemplate.mitreTechniques = $mitreTechniques }
        
        # Configure entity mappings
        if ($impactedAssets) {
            $body.detectionAction.alertTemplate.impactedAssets = $impactedAssets
        }
        
        if ($relatedEvidence) {
            $body.detectionAction.alertTemplate.relatedEvidence = $relatedEvidence
        }
    }
    
    $jsonBody = $body | ConvertTo-Json -Depth 10
    
    $Headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type" = "application/json"
    }
    
    Write-Host "[*] Creating rule: $displayName" -ForegroundColor Yellow
    
    try {
        $return = Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules" -Body $jsonBody -Headers $Headers
        Write-Host "[✓] Rule created successfully" -ForegroundColor Green
        return $return
    } catch {
        Write-Host "[!] Failed to create rule: $_" -ForegroundColor Red
        Write-Host "Request body:" -ForegroundColor Yellow
        Write-Host $jsonBody
        return $null
    }
}

# Export detection rules to JSON format
function Export-Rules {
    param(
        [array]$Rules,
        [string]$OutputPath,
        [bool]$AsSeparateFiles = $false
    )
    
    Write-Host "`n[*] Exporting rules..." -ForegroundColor Yellow
    
    if ($AsSeparateFiles) {
        # Export each rule as a separate file
        $folderPath = $OutputPath
        if (-not (Test-Path $folderPath)) {
            New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
        }
        
        Write-Host "[*] Exporting to folder: $folderPath" -ForegroundColor Cyan
        
        $exportedCount = 0
        foreach ($rule in $Rules) {
            Write-Host "    Exporting: $($rule.displayName)" -ForegroundColor Gray
            
            # Generate valid filename from rule display name
            $fileName = $rule.displayName -replace '[^\w\s-]', '_'
            $fileName = $fileName -replace '\s+', '_'
            $filePath = Join-Path $folderPath "$fileName.json"
            
            # Structure rule data for export
            $ruleData = @{
                metadata = @{
                    exportDate = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    source = "Microsoft Graph API"
                }
                rule = @{
                    displayName = $rule.displayName
                    isEnabled = $rule.isEnabled
                    queryCondition = $rule.queryCondition
                    schedule = $rule.schedule
                    detectionAction = $rule.detectionAction
                    createdDateTime = $rule.createdDateTime
                    lastModifiedDateTime = $rule.lastModifiedDateTime
                    id = $rule.id
                }
            }
            
            # Identify entity mappings if present
            if ($rule.detectionAction -and $rule.detectionAction.alertTemplate) {
                if ($rule.detectionAction.alertTemplate.impactedAssets) {
                    Write-Host "      → Found impacted assets (entity mappings)" -ForegroundColor Cyan
                }
                if ($rule.detectionAction.alertTemplate.relatedEvidence) {
                    Write-Host "      → Found related evidence" -ForegroundColor Cyan
                }
            }
            
            # Save rule to individual file
            $ruleJson = $ruleData | ConvertTo-Json -Depth 20
            $ruleJson | Out-File -FilePath $filePath -Encoding UTF8
            Write-Host "      → Saved to: $fileName.json" -ForegroundColor Green
            
            $exportedCount++
        }
        
        Write-Host "[✓] Exported $exportedCount rules to: $folderPath" -ForegroundColor Green
        
        return $folderPath
        
    } else {
        # Export all rules to a single file
        $fullOutputPath = if ($OutputPath -notlike "*.json") { "$OutputPath.json" } else { $OutputPath }
        
        $exportData = @{
            metadata = @{
                exportDate = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                rulesCount = $Rules.Count
                source = "Microsoft Graph API"
                exportType = "Single File"
            }
            rules = @()
        }
        
        foreach ($rule in $Rules) {
            Write-Host "    Exporting: $($rule.displayName)" -ForegroundColor Gray
            
            # Preserve all rule properties
            $exportRule = @{
                displayName = $rule.displayName
                isEnabled = $rule.isEnabled
                queryCondition = $rule.queryCondition
                schedule = $rule.schedule
                detectionAction = $rule.detectionAction
                createdDateTime = $rule.createdDateTime
                lastModifiedDateTime = $rule.lastModifiedDateTime
                id = $rule.id
            }
            
            # Identify entity mappings if present
            if ($rule.detectionAction -and $rule.detectionAction.alertTemplate) {
                if ($rule.detectionAction.alertTemplate.impactedAssets) {
                    Write-Host "      → Found impacted assets (entity mappings)" -ForegroundColor Cyan
                }
                if ($rule.detectionAction.alertTemplate.relatedEvidence) {
                    Write-Host "      → Found related evidence" -ForegroundColor Cyan
                }
            }
            
            $exportData.rules += $exportRule
        }
        
        $json = $exportData | ConvertTo-Json -Depth 20
        $json | Out-File -FilePath $fullOutputPath -Encoding UTF8
        
        Write-Host "[✓] Rules exported to: $fullOutputPath" -ForegroundColor Green
        return $fullOutputPath
    }
}

# Import detection rules from JSON file
function Import-Rules {
    param(
        [string]$ImportPath,
        [string]$Token
    )
    
    if (-not (Test-Path $ImportPath)) {
        Write-Host "[!] Import file not found: $ImportPath" -ForegroundColor Red
        return
    }
    
    Write-Host "[*] Loading rules from: $ImportPath" -ForegroundColor Yellow
    $importData = Get-Content $ImportPath | ConvertFrom-Json
    
    if (-not $importData.rules -and -not $importData.rule) {
        Write-Host "[!] No rules found in import file" -ForegroundColor Red
        return
    }
    
    # Support both single file and individual rule file formats
    $rulesToImport = if ($importData.rules) { $importData.rules } else { @($importData.rule) }
    
    Write-Host "[*] Found $($rulesToImport.Count) rule(s) to import" -ForegroundColor Yellow
    
    # Retrieve existing rules to check for duplicates
    $existingRules = Get-DetectionRules -Token $Token -IncludeDisabled:$true
    $existingRuleNames = $existingRules | Select-Object -ExpandProperty displayName
    
    foreach ($rule in $rulesToImport) {
        Write-Host "`n[*] Processing: $($rule.displayName)" -ForegroundColor Yellow
        
        # Handle duplicate rule names
        if ($existingRuleNames -contains $rule.displayName) {
            Write-Host "[!] Rule already exists: $($rule.displayName)" -ForegroundColor Yellow
            $overwrite = Read-Host "    Do you want to create a duplicate? (y/n)"
            if ($overwrite -ne 'y') {
                Write-Host "    Skipping..." -ForegroundColor Gray
                continue
            }
            # Append timestamp to create unique name for duplicate
            $ruleName = "$($rule.displayName)_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            Write-Host "    Creating duplicate as: $ruleName" -ForegroundColor Cyan
        } else {
            $ruleName = $rule.displayName
        }
        
        # Build parameters for rule creation
        $params = @{
            displayName = $ruleName
            isEnabled = $rule.isEnabled
            queryText = $rule.queryCondition.queryText
            period = $rule.schedule.period
            token = $Token
        }
        
        # Process optional alert template properties
        if ($rule.detectionAction -and $rule.detectionAction.alertTemplate) {
            $template = $rule.detectionAction.alertTemplate
            
            if ($template.title) { $params.alertTitle = $template.title }
            if ($template.description) { $params.alertDescription = $template.description }
            if ($template.severity) { $params.severity = $template.severity }
            if ($template.category) { $params.category = $template.category }
            if ($template.mitreTechniques) { $params.mitreTechniques = $template.mitreTechniques }
            
            # Process entity mappings
            if ($template.impactedAssets) {
                $params.impactedAssets = $template.impactedAssets
                Write-Host "    → Including impacted assets (entity mappings)" -ForegroundColor Cyan
            }
            
            if ($template.relatedEvidence) {
                $params.relatedEvidence = $template.relatedEvidence
                Write-Host "    → Including related evidence" -ForegroundColor Cyan
            }
        }
        
        $result = New-DetectionRule @params
        
        if ($result) {
            Write-Host "[✓] Successfully imported: $ruleName" -ForegroundColor Green
        }
    }
}

# Main execution function
function Main {
    Write-Host "Action: $Action" -ForegroundColor Yellow
    
    # Collect required credentials
    if (-not $TenantId) { $TenantId = Read-Host "Enter Tenant ID" }
    if (-not $ClientId) { $ClientId = Read-Host "Enter Client ID" }
    if (-not $ClientSecret) { 
        $secureSecret = Read-Host "Enter Client Secret" -AsSecureString
        $ClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret))
    }
    
    # Authenticate and retrieve access token
    $token = Get-AccessToken -tenantId $TenantId -clientId $ClientId -clientSecret $ClientSecret
    
    if (-not $token) {
        Write-Host "[!] Failed to obtain token" -ForegroundColor Red
        return
    }
    
    switch ($Action) {
        "Export" {
            $rules = Get-DetectionRules -Token $token -IncludeDisabled:$IncludeDisabled
            
            if ($rules -and $rules.Count -gt 0) {
                Export-Rules -Rules $rules -OutputPath $OutputPath -AsSeparateFiles:$Single
                
                # Display export summary
                Write-Host "`n[*] Export Summary:" -ForegroundColor Cyan
                Write-Host "    Total rules exported: $($rules.Count)" -ForegroundColor White
                Write-Host "    Export type: $(if ($Single) { 'Separate files' } else { 'Single file' })" -ForegroundColor White
                
                $rulesWithMappings = $rules | Where-Object { 
                    $_.detectionAction -and 
                    $_.detectionAction.alertTemplate -and 
                    ($_.detectionAction.alertTemplate.impactedAssets -or $_.detectionAction.alertTemplate.relatedEvidence)
                }
                
                if ($rulesWithMappings) {
                    Write-Host "    Rules with entity mappings: $($rulesWithMappings.Count)" -ForegroundColor White
                }
            } else {
                Write-Host "[!] No rules found to export" -ForegroundColor Yellow
            }
        }
        
        "Import" {
            if (-not $ImportPath) {
                $ImportPath = Read-Host "Enter path to import file"
            }
            Import-Rules -ImportPath $ImportPath -Token $token
        }
        
        "List" {
            $rules = Get-DetectionRules -Token $token -IncludeDisabled:$IncludeDisabled
            
            if ($rules -and $rules.Count -gt 0) {
                Write-Host "`n[*] Custom Detection Rules:" -ForegroundColor Cyan
                foreach ($rule in $rules) {
                    Write-Host "`n    $($rule.displayName)" -ForegroundColor White
                    Write-Host "      ID: $($rule.id)" -ForegroundColor Gray
                    Write-Host "      Enabled: $($rule.isEnabled)" -ForegroundColor Gray
                    Write-Host "      Schedule: $($rule.schedule.period)" -ForegroundColor Gray
                    
                    if ($rule.detectionAction -and $rule.detectionAction.alertTemplate) {
                        if ($rule.detectionAction.alertTemplate.impactedAssets) {
                            Write-Host "      ✓ Has entity mappings" -ForegroundColor Green
                        }
                    }
                }
            }
        }
    }
}

# Execute main function
Main