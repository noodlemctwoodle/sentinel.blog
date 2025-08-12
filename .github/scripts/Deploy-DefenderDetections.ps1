<#
.SYNOPSIS
    Deploy Microsoft Defender XDR Custom Detection Rules from repository

.DESCRIPTION
    Automated deployment script for Defender XDR custom detections
    Used by GitHub Actions for CI/CD pipeline

.PARAMETER TenantId
    Entra ID Tenant ID

.PARAMETER ClientId
    App Registration Client ID

.PARAMETER ClientSecret
    App Registration Client Secret

.PARAMETER RulesPath
    Path to folder containing detection rule JSON files
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $true)]
    [string]$ClientId,
    
    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,
    
    [Parameter(Mandatory = $true)]
    [string]$RulesPath
)

# Import the main detection management script
. "$PSScriptRoot\DefenderXDR-CustomDetections.ps1"

Write-Host "=== Defender XDR Custom Detections Deployment ===" -ForegroundColor Cyan
Write-Host "Rules Path: $RulesPath" -ForegroundColor Yellow

# Authenticate to Microsoft Graph
Write-Host "`n[*] Authenticating to Microsoft Graph..." -ForegroundColor Yellow
$token = Get-AccessToken -tenantId $TenantId -clientId $ClientId -clientSecret $ClientSecret

if (-not $token) {
    Write-Error "Authentication failed. Exiting."
    exit 1
}

# Get existing rules to check for duplicates
Write-Host "[*] Fetching existing rules..." -ForegroundColor Yellow
$existingRules = Get-DetectionRules -Token $token -IncludeDisabled $true
$existingRuleNames = $existingRules | Select-Object -ExpandProperty displayName

# Get all JSON files from the rules path
$ruleFiles = Get-ChildItem -Path $RulesPath -Filter "*.json" -Recurse

if ($ruleFiles.Count -eq 0) {
    Write-Warning "No JSON files found in $RulesPath"
    exit 0
}

Write-Host "[*] Found $($ruleFiles.Count) rule file(s) to deploy" -ForegroundColor Cyan

$deployed = 0
$skipped = 0
$failed = 0

# Process each rule file
foreach ($file in $ruleFiles) {
    Write-Host "`n[*] Processing: $($file.Name)" -ForegroundColor Yellow
    
    try {
        # Load rule file
        $ruleContent = Get-Content $file.FullName -Raw | ConvertFrom-Json
        
        # Handle both single rule and multiple rules formats
        $rules = if ($ruleContent.rules) { $ruleContent.rules } elseif ($ruleContent.rule) { @($ruleContent.rule) } else { @($ruleContent) }
        
        foreach ($rule in $rules) {
            Write-Host "  Deploying: $($rule.displayName)" -ForegroundColor Gray
            
            # Skip if rule already exists
            if ($existingRuleNames -contains $rule.displayName) {
                Write-Host "    [!] Already exists, skipping..." -ForegroundColor Yellow
                $skipped++
                continue
            }
            
            # Build parameters for rule creation
            $params = @{
                displayName = $rule.displayName
                isEnabled = $rule.isEnabled
                queryText = $rule.queryCondition.queryText
                period = $rule.schedule.period
                token = $token
            }
            
            # Add optional alert template properties if present
            if ($rule.detectionAction -and $rule.detectionAction.alertTemplate) {
                $template = $rule.detectionAction.alertTemplate
                if ($template.title) { $params.alertTitle = $template.title }
                if ($template.description) { $params.alertDescription = $template.description }
                if ($template.severity) { $params.severity = $template.severity }
                if ($template.category) { $params.category = $template.category }
                if ($template.mitreTechniques) { $params.mitreTechniques = $template.mitreTechniques }
                if ($template.impactedAssets) { $params.impactedAssets = $template.impactedAssets }
                if ($template.relatedEvidence) { $params.relatedEvidence = $template.relatedEvidence }
            }
            
            # Create the rule
            $result = New-DetectionRule @params
            
            if ($result) {
                Write-Host "    [✓] Successfully deployed" -ForegroundColor Green
                $deployed++
            } else {
                Write-Host "    [✗] Deployment failed" -ForegroundColor Red
                $failed++
            }
        }
    } catch {
        Write-Host "  [✗] Error: $_" -ForegroundColor Red
        $failed++
    }
}

# Display summary
Write-Host "`n=== Deployment Summary ===" -ForegroundColor Cyan
Write-Host "Deployed: $deployed" -ForegroundColor Green
Write-Host "Skipped: $skipped" -ForegroundColor Yellow
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Gray" })

# Exit with error code if any deployments failed
if ($failed -gt 0) {
    exit 1
}

Write-Host "`n[✓] Deployment completed successfully" -ForegroundColor Green