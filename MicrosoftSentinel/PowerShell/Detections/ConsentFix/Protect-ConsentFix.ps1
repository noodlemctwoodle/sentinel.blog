<#
.SYNOPSIS
    PowerShell script to protect your Entra ID tenant against ConsentFix attacks

.DESCRIPTION
    This script helps protect your Microsoft Entra ID tenant against ConsentFix/AuthCodeFix attacks
    by managing service principals for vulnerable Microsoft first-party applications.
    
    ConsentFix is an OAuth attack that exploits pre-consented Microsoft applications to steal
    authorisation codes. This script implements the primary mitigation by requiring user assignment
    for vulnerable applications.

.PARAMETER Action
    The action to perform:
    - Audit: Check current security status
    - Protect: Implement protection on all vulnerable apps
    - GrantAccess: Assign a user to a specific application
    - Verify: Test that protection is working correctly
    - All: Run audit, protect, and verify in sequence

.PARAMETER UserPrincipalName
    User Principal Name for granting access (used with -Action GrantAccess)

.PARAMETER ApplicationName
    Application to grant access to (used with -Action GrantAccess)

.PARAMETER WhatIf
    Show what would be done without making changes

.EXAMPLE
    .\Protect-ConsentFix.ps1 -Action Audit
    Audits the current security status of your tenant

.EXAMPLE
    .\Protect-ConsentFix.ps1 -Action Protect
    Implements protection on all vulnerable applications

.EXAMPLE
    .\Protect-ConsentFix.ps1 -Action GrantAccess -UserPrincipalName "admin@contoso.com" -ApplicationName "Azure CLI"
    Grants a specific user access to Azure CLI

.EXAMPLE
    .\Protect-ConsentFix.ps1 -Action All
    Runs a complete audit, implements protection, and verifies the result

.NOTES
    Author: Sentinel.blog
    Version: 1.0
    Requires: Microsoft.Graph.Applications module
    Requires: Global Administrator or Privileged Role Administrator permissions
    
.LINK
    https://sentinel.blog
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Audit', 'Protect', 'GrantAccess', 'Verify', 'All')]
    [string]$Action = 'Audit',
    
    [Parameter(Mandatory = $false)]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Azure CLI', 'Azure PowerShell', 'Visual Studio', 'Visual Studio Code', 'Microsoft Teams PowerShell')]
    [string]$ApplicationName
)

#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Users

#region Helper Functions

function Write-Header {
    param([string]$Text)
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ("=" * 80) -ForegroundColor Cyan
}

function Write-SubHeader {
    param([string]$Text)
    Write-Host "`n$Text" -ForegroundColor Yellow
    Write-Host ("-" * 60) -ForegroundColor Yellow
}

#endregion

#region Core Functions

function Get-VulnerableApplications {
    <#
    .SYNOPSIS
        Returns a hashtable of Microsoft first-party applications vulnerable to ConsentFix
    #>
    return @{
        "04b07795-8ddb-461a-bbee-02f9e1bf7b46" = @{
            Name        = "Azure CLI"
            Description = "Command-line interface for Azure management"
            Risk        = "High"
        }
        "1950a258-227b-4e31-a9cf-717495945fc2" = @{
            Name        = "Azure PowerShell"
            Description = "PowerShell module for Azure administration"
            Risk        = "High"
        }
        "04f0c124-f2bc-4f59-8241-bf6df9866bbd" = @{
            Name        = "Visual Studio"
            Description = "Microsoft development environment"
            Risk        = "Medium"
        }
        "aebc6443-996d-45c2-90f0-388ff96faa56" = @{
            Name        = "Visual Studio Code"
            Description = "Lightweight code editor"
            Risk        = "Medium"
        }
        "12128f48-ec9e-42f0-b203-ea49fb6af367" = @{
            Name        = "Microsoft Teams PowerShell"
            Description = "PowerShell module for Teams administration"
            Risk        = "Medium"
        }
    }
}

function Get-TenantSecurityStatus {
    <#
    .SYNOPSIS
        Audits the current state of vulnerable applications in your tenant
    #>
    
    Write-Header "Auditing Tenant for Vulnerable Applications"
    
    $vulnerableApps = Get-VulnerableApplications
    $results = @()
    
    foreach ($appId in $vulnerableApps.Keys) {
        $appInfo = $vulnerableApps[$appId]
        
        Write-SubHeader "Checking: $($appInfo.Name)"
        Write-Host "  App ID: $appId" -ForegroundColor Gray
        
        try {
            $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
            
            if ($servicePrincipal) {
                $assignmentRequired = $servicePrincipal.AppRoleAssignmentRequired
                $status = if ($assignmentRequired) { "PROTECTED" } else { "VULNERABLE" }
                $colour = if ($assignmentRequired) { "Green" } else { "Red" }
                
                Write-Host "  Status: " -NoNewline
                Write-Host $status -ForegroundColor $colour
                Write-Host "  Object ID: $($servicePrincipal.Id)" -ForegroundColor Gray
                
                # Get assignment count
                $assignments = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $servicePrincipal.Id -ErrorAction SilentlyContinue
                Write-Host "  Assigned Users: $($assignments.Count)" -ForegroundColor Gray
                
                $results += [PSCustomObject]@{
                    ApplicationName      = $appInfo.Name
                    AppId                = $appId
                    ObjectId             = $servicePrincipal.Id
                    AssignmentRequired   = $assignmentRequired
                    Status               = $status
                    RiskLevel            = $appInfo.Risk
                    AssignedUsers        = $assignments.Count
                    Action               = if ($assignmentRequired) { "None required" } else { "Needs protection" }
                }
            }
            else {
                Write-Host "  Status: " -NoNewline
                Write-Host "NOT PRESENT" -ForegroundColor Yellow
                Write-Host "  Action: Will be created proactively" -ForegroundColor Yellow
                
                $results += [PSCustomObject]@{
                    ApplicationName      = $appInfo.Name
                    AppId                = $appId
                    ObjectId             = "N/A"
                    AssignmentRequired   = $false
                    Status               = "NOT PRESENT"
                    RiskLevel            = $appInfo.Risk
                    AssignedUsers        = 0
                    Action               = "Create and protect"
                }
            }
        }
        catch {
            Write-Host "  Error: $_" -ForegroundColor Red
        }
    }
    
    # Summary
    Write-Header "Summary"
    $protected = ($results | Where-Object { $_.Status -eq "PROTECTED" }).Count
    $vulnerable = ($results | Where-Object { $_.Status -eq "VULNERABLE" }).Count
    $notPresent = ($results | Where-Object { $_.Status -eq "NOT PRESENT" }).Count
    
    Write-Host "Protected applications:   " -NoNewline
    Write-Host $protected -ForegroundColor Green
    Write-Host "Vulnerable applications:  " -NoNewline
    Write-Host $vulnerable -ForegroundColor Red
    Write-Host "Applications not present: " -NoNewline
    Write-Host $notPresent -ForegroundColor Yellow
    
    return $results
}

function Invoke-ConsentFixProtection {
    <#
    .SYNOPSIS
        Protects against ConsentFix by requiring user assignment for vulnerable applications
    #>
    
    [CmdletBinding(SupportsShouldProcess)]
    param()
    
    Write-Header "Implementing ConsentFix Protection"
    
    $vulnerableApps = Get-VulnerableApplications
    $protected = 0
    $created = 0
    $errors = 0
    
    foreach ($appId in $vulnerableApps.Keys) {
        $appInfo = $vulnerableApps[$appId]
        
        Write-SubHeader "Processing: $($appInfo.Name)"
        Write-Host "  App ID: $appId" -ForegroundColor Gray
        Write-Host "  Risk Level: $($appInfo.Risk)" -ForegroundColor Gray
        
        try {
            # Check if service principal exists
            $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
            
            if (-not $servicePrincipal) {
                if ($PSCmdlet.ShouldProcess($appInfo.Name, "Create service principal")) {
                    Write-Host "  Creating service principal..." -ForegroundColor Cyan
                    
                    $servicePrincipal = New-MgServicePrincipal -AppId $appId -ErrorAction Stop
                    $created++
                    
                    Write-Host "  Service principal created successfully" -ForegroundColor Green
                    Write-Host "  Object ID: $($servicePrincipal.Id)" -ForegroundColor Gray
                    
                    # Small delay to allow replication
                    Start-Sleep -Seconds 2
                }
            }
            else {
                Write-Host "  Service principal exists" -ForegroundColor Gray
                Write-Host "  Object ID: $($servicePrincipal.Id)" -ForegroundColor Gray
            }
            
            # Check current assignment requirement
            if ($servicePrincipal.AppRoleAssignmentRequired) {
                Write-Host "  Already protected - user assignment required" -ForegroundColor Green
            }
            else {
                if ($PSCmdlet.ShouldProcess($appInfo.Name, "Require user assignment")) {
                    Write-Host "  Enforcing user assignment requirement..." -ForegroundColor Cyan
                    
                    Update-MgServicePrincipal `
                        -ServicePrincipalId $servicePrincipal.Id `
                        -AppRoleAssignmentRequired:$true `
                        -ErrorAction Stop
                    
                    $protected++
                    Write-Host "  Protection applied successfully" -ForegroundColor Green
                }
            }
        }
        catch {
            $errors++
            Write-Host "  Error: $_" -ForegroundColor Red
        }
    }
    
    # Summary
    Write-Header "Protection Summary"
    Write-Host "Service principals created: " -NoNewline
    Write-Host $created -ForegroundColor $(if ($created -gt 0) { "Green" } else { "Gray" })
    Write-Host "Applications protected:     " -NoNewline
    Write-Host $protected -ForegroundColor $(if ($protected -gt 0) { "Green" } else { "Gray" })
    Write-Host "Errors encountered:         " -NoNewline
    Write-Host $errors -ForegroundColor $(if ($errors -gt 0) { "Red" } else { "Gray" })
    
    if ($errors -eq 0 -and ($created -gt 0 -or $protected -gt 0)) {
        Write-Host "`nConsentFix mitigation successfully implemented!" -ForegroundColor Green
        Write-Host "Remember to assign legitimate users who need access to these tools." -ForegroundColor Yellow
    }
}

function Grant-ApplicationAccess {
    <#
    .SYNOPSIS
        Assigns a user to a protected Microsoft first-party application
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory)]
        [ValidateSet('Azure CLI', 'Azure PowerShell', 'Visual Studio', 'Visual Studio Code', 'Microsoft Teams PowerShell')]
        [string]$ApplicationName
    )
    
    Write-Header "Granting Application Access"
    
    try {
        # Get user
        Write-SubHeader "Looking up user: $UserPrincipalName"
        $user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction Stop
        
        if (-not $user) {
            throw "User not found: $UserPrincipalName"
        }
        
        Write-Host "  Found: $($user.DisplayName)" -ForegroundColor Green
        Write-Host "  User ID: $($user.Id)" -ForegroundColor Gray
        
        # Get application ID
        $vulnerableApps = Get-VulnerableApplications
        $appId = ($vulnerableApps.GetEnumerator() | Where-Object { $_.Value.Name -eq $ApplicationName }).Key
        
        if (-not $appId) {
            throw "Application not found: $ApplicationName"
        }
        
        Write-SubHeader "Looking up application: $ApplicationName"
        $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction Stop
        
        if (-not $servicePrincipal) {
            throw "Service principal not found. Run 'Protect-ConsentFix.ps1 -Action Protect' first."
        }
        
        Write-Host "  Found: $($servicePrincipal.DisplayName)" -ForegroundColor Green
        Write-Host "  App ID: $appId" -ForegroundColor Gray
        Write-Host "  Object ID: $($servicePrincipal.Id)" -ForegroundColor Gray
        
        # Check if already assigned
        $existingAssignment = Get-MgServicePrincipalAppRoleAssignedTo `
            -ServicePrincipalId $servicePrincipal.Id `
            -Filter "principalId eq '$($user.Id)'" `
            -ErrorAction SilentlyContinue
        
        if ($existingAssignment) {
            Write-Host "`nUser already has access to $ApplicationName" -ForegroundColor Yellow
            return
        }
        
        # Create assignment
        Write-SubHeader "Assigning user to application"
        
        $assignment = New-MgServicePrincipalAppRoleAssignedTo `
            -ServicePrincipalId $servicePrincipal.Id `
            -PrincipalId $user.Id `
            -ResourceId $servicePrincipal.Id `
            -AppRoleId "00000000-0000-0000-0000-000000000000" `
            -ErrorAction Stop
        
        Write-Host "`nAccess granted successfully!" -ForegroundColor Green
        Write-Host "  User: $($user.DisplayName)" -ForegroundColor Gray
        Write-Host "  Application: $ApplicationName" -ForegroundColor Gray
        Write-Host "  Assignment ID: $($assignment.Id)" -ForegroundColor Gray
    }
    catch {
        Write-Host "`nError: $_" -ForegroundColor Red
        throw
    }
}

function Test-ConsentFixProtection {
    <#
    .SYNOPSIS
        Verifies ConsentFix protection is properly configured
    #>
    
    Write-Header "Verifying ConsentFix Protection"
    
    $vulnerableApps = Get-VulnerableApplications
    $allProtected = $true
    $results = @()
    
    foreach ($appId in $vulnerableApps.Keys) {
        $appInfo = $vulnerableApps[$appId]
        
        try {
            $servicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
            
            if (-not $servicePrincipal) {
                $allProtected = $false
                Write-Host "`n[!] " -NoNewline -ForegroundColor Red
                Write-Host "$($appInfo.Name): NOT PROTECTED" -ForegroundColor Red
                Write-Host "    Service principal doesn't exist" -ForegroundColor Gray
                
                $results += [PSCustomObject]@{
                    Application = $appInfo.Name
                    Status      = "NOT PROTECTED"
                    Issue       = "Service principal not created"
                }
            }
            elseif (-not $servicePrincipal.AppRoleAssignmentRequired) {
                $allProtected = $false
                Write-Host "`n[!] " -NoNewline -ForegroundColor Red
                Write-Host "$($appInfo.Name): VULNERABLE" -ForegroundColor Red
                Write-Host "    User assignment not required" -ForegroundColor Gray
                
                $results += [PSCustomObject]@{
                    Application = $appInfo.Name
                    Status      = "VULNERABLE"
                    Issue       = "Assignment not required"
                }
            }
            else {
                Write-Host "`n[✓] " -NoNewline -ForegroundColor Green
                Write-Host "$($appInfo.Name): PROTECTED" -ForegroundColor Green
                Write-Host "    User assignment required" -ForegroundColor Gray
                
                # Check how many users are assigned
                $assignments = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $servicePrincipal.Id -ErrorAction SilentlyContinue
                Write-Host "    Assigned users: $($assignments.Count)" -ForegroundColor Gray
                
                $results += [PSCustomObject]@{
                    Application   = $appInfo.Name
                    Status        = "PROTECTED"
                    Issue         = "None"
                    AssignedUsers = $assignments.Count
                }
            }
        }
        catch {
            Write-Host "`n[!] Error checking $($appInfo.Name): $_" -ForegroundColor Red
        }
    }
    
    Write-Header "Verification Summary"
    
    if ($allProtected) {
        Write-Host "All applications are properly protected against ConsentFix!" -ForegroundColor Green
    }
    else {
        Write-Host "Some applications are not properly protected." -ForegroundColor Red
        Write-Host "Run 'Protect-ConsentFix.ps1 -Action Protect' to secure your tenant." -ForegroundColor Yellow
    }
    
    return $results
}

#endregion

#region Main Execution

# Display banner
Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                        ConsentFix Protection Script                          ║
║                                                                              ║
║  Protect your Microsoft Entra ID tenant against OAuth authorisation         ║
║  code theft attacks targeting Microsoft first-party applications             ║
║                                                                              ║
║  Source: https://sentinel.blog                                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Check if already connected to Microsoft Graph
$context = Get-MgContext
if (-not $context) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Write-Host "Required permissions: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All`n" -ForegroundColor Gray
    
    try {
        Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -ErrorAction Stop
        $context = Get-MgContext
        Write-Host "Connected successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to connect to Microsoft Graph: $_" -ForegroundColor Red
        exit 1
    }
}

Write-Host "`nConnected to tenant: " -NoNewline
Write-Host $context.TenantId -ForegroundColor Green
Write-Host "Authenticated as: " -NoNewline
Write-Host $context.Account -ForegroundColor Green

# Execute requested action
switch ($Action) {
    'Audit' {
        $results = Get-TenantSecurityStatus
        $results | Format-Table -AutoSize
    }
    
    'Protect' {
        Invoke-ConsentFixProtection
    }
    
    'GrantAccess' {
        if (-not $UserPrincipalName -or -not $ApplicationName) {
            Write-Host "`nError: -UserPrincipalName and -ApplicationName are required for GrantAccess action" -ForegroundColor Red
            Write-Host "Example: .\Protect-ConsentFix.ps1 -Action GrantAccess -UserPrincipalName 'admin@contoso.com' -ApplicationName 'Azure CLI'" -ForegroundColor Yellow
            exit 1
        }
        Grant-ApplicationAccess -UserPrincipalName $UserPrincipalName -ApplicationName $ApplicationName
    }
    
    'Verify' {
        $results = Test-ConsentFixProtection
        Write-Host "`n"
        $results | Format-Table -AutoSize
    }
    
    'All' {
        # Run complete workflow
        Write-Host "`nRunning complete ConsentFix protection workflow...`n" -ForegroundColor Cyan
        
        # Step 1: Audit
        $auditResults = Get-TenantSecurityStatus
        $auditResults | Format-Table -AutoSize
        
        # Step 2: Protect (if needed)
        $vulnerable = $auditResults | Where-Object { $_.Status -ne "PROTECTED" }
        if ($vulnerable) {
            Write-Host "`nFound $($vulnerable.Count) vulnerable application(s). Proceeding with protection..." -ForegroundColor Yellow
            Read-Host "Press Enter to continue or Ctrl+C to cancel"
            Invoke-ConsentFixProtection
        }
        
        # Step 3: Verify
        Start-Sleep -Seconds 3
        $verifyResults = Test-ConsentFixProtection
        Write-Host "`n"
        $verifyResults | Format-Table -AutoSize
        
        # Final recommendations
        Write-Header "Next Steps"
        Write-Host "1. Review the protected applications above" -ForegroundColor Yellow
        Write-Host "2. Assign legitimate users who need CLI/PowerShell access using:" -ForegroundColor Yellow
        Write-Host "   .\Protect-ConsentFix.ps1 -Action GrantAccess -UserPrincipalName 'user@domain.com' -ApplicationName 'Azure CLI'" -ForegroundColor Gray
        Write-Host "3. Consider implementing additional security layers:" -ForegroundColor Yellow
        Write-Host "   - Conditional Access policies for trusted locations" -ForegroundColor Gray
        Write-Host "   - Token Protection for Windows devices" -ForegroundColor Gray
        Write-Host "   - Monitoring and detection with Microsoft Sentinel" -ForegroundColor Gray
    }
}

Write-Host "`n"

#endregion
