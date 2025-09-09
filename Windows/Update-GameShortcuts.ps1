<#
.SYNOPSIS
    Updates desktop shortcuts to change drive letter paths from D:\Games\ to I:\Games\

.DESCRIPTION
    This PowerShell script provides a function to update Windows desktop shortcuts when
    a drive letter changes. It can safely test changes before applying them and process
    specific files or all shortcuts at once.

.PARAMETER OldPath
    The old path to replace (default: "D:\Games\")

.PARAMETER NewPath  
    The new path to use (default: "I:\Games\")

.PARAMETER DesktopPath
    Path to desktop folder (default: current user's desktop)

.PARAMETER TestFiles
    Array of specific shortcut filenames to process (e.g., @('Game1.lnk', 'Game2.lnk'))

.PARAMETER WhatIf
    Shows what would change without making any modifications (safe preview mode)

.PARAMETER Recursive
    Include shortcuts in subfolders of the desktop

.PARAMETER Force
    Update shortcuts even if the new target path doesn't exist

.EXAMPLES
    # Safe preview - see what would change
    Update-GameShortcuts -WhatIf

    # Test on specific shortcuts only (safe)
    Update-GameShortcuts -TestFiles @('Steam Game.lnk', 'Epic Game.lnk') -WhatIf

    # Actually update specific shortcuts after testing
    Update-GameShortcuts -TestFiles @('Steam Game.lnk', 'Epic Game.lnk')

    # Update all shortcuts (after testing!)
    Update-GameShortcuts

    # Include shortcuts in subfolders
    Update-GameShortcuts -Recursive

    # Custom paths
    Update-GameShortcuts -OldPath 'E:\OldGames\' -NewPath 'F:\NewGames\'

    # Force update even if target doesn't exist
    Update-GameShortcuts -Force

.NOTES
    File Name      : UpdateGameShortcuts.ps1
    Author         : noodlemctwoodle
    Prerequisite   : PowerShell 5.0 or higher
    
    RECOMMENDED WORKFLOW:
    1. Run with -WhatIf first to preview changes
    2. Test on 1-2 shortcuts with -TestFiles
    3. Apply to all shortcuts once confirmed working

.LINK
    About Windows Shortcuts: https://docs.microsoft.com/en-us/windows/desktop/shell/links
#>

# PowerShell script to update desktop shortcuts from D:\Games\ to I:\Games\
# With function and switches for testing and batch processing

function Update-GameShortcuts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OldPath = "D:\Games\",
        
        [Parameter(Mandatory=$false)]
        [string]$NewPath = "I:\Games\",
        
        [Parameter(Mandatory=$false)]
        [string]$DesktopPath = [Environment]::GetFolderPath("Desktop"),
        
        [Parameter(Mandatory=$false)]
        [string[]]$TestFiles = @(),
        
        [Parameter(Mandatory=$false)]
        [switch]$WhatIf,
        
        [Parameter(Mandatory=$false)]
        [switch]$Recursive,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    
    Write-Host "=== Desktop Shortcut Updater ===" -ForegroundColor Cyan
    Write-Host "Desktop path: $DesktopPath" -ForegroundColor Yellow
    Write-Host "Updating paths from: $OldPath" -ForegroundColor Red
    Write-Host "Updating paths to: $NewPath" -ForegroundColor Green
    
    if ($WhatIf) {
        Write-Host "MODE: WHATIF (No changes will be made)" -ForegroundColor Magenta
    }
    if ($TestFiles.Count -gt 0) {
        Write-Host "MODE: TESTING specific files" -ForegroundColor Magenta
    }
    Write-Host ""
    
    # Create COM object for working with shortcuts
    $shell = New-Object -ComObject WScript.Shell
    
    # Determine which shortcuts to process
    if ($TestFiles.Count -gt 0) {
        # Test mode - only process specified files
        $shortcuts = @()
        foreach ($testFile in $TestFiles) {
            $fullPath = Join-Path $DesktopPath $testFile
            if (Test-Path $fullPath) {
                $shortcuts += Get-Item $fullPath
            }
            else {
                Write-Host "WARNING: Test file not found: $testFile" -ForegroundColor Red
            }
        }
    }
    else {
        # Get all .lnk files on the desktop
        if ($Recursive) {
            $shortcuts = Get-ChildItem -Path $DesktopPath -Filter "*.lnk" -Recurse
        }
        else {
            $shortcuts = Get-ChildItem -Path $DesktopPath -Filter "*.lnk"
        }
    }
    
    $updatedCount = 0
    $totalShortcuts = $shortcuts.Count
    $gameShortcuts = 0
    
    Write-Host "Found $totalShortcuts shortcut(s) to process" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($shortcut in $shortcuts) {
        try {
            # Load the shortcut
            $link = $shell.CreateShortcut($shortcut.FullName)
            
            # Check if the target path contains the old game path
            if ($link.TargetPath -like "$OldPath*") {
                $gameShortcuts++
                Write-Host "[$gameShortcuts] Processing: $($shortcut.Name)" -ForegroundColor Yellow
                Write-Host "    Location: $($shortcut.DirectoryName)" -ForegroundColor Gray
                Write-Host "    Old target: $($link.TargetPath)" -ForegroundColor Red
                
                # Calculate new paths
                $newTargetPath = $link.TargetPath.Replace($OldPath, $NewPath)
                $newWorkingDir = $link.WorkingDirectory
                
                if ($link.WorkingDirectory -like "$OldPath*") {
                    $newWorkingDir = $link.WorkingDirectory.Replace($OldPath, $NewPath)
                    Write-Host "    Old working dir: $($link.WorkingDirectory)" -ForegroundColor Red
                    Write-Host "    New working dir: $newWorkingDir" -ForegroundColor Green
                }
                
                Write-Host "    New target: $newTargetPath" -ForegroundColor Green
                
                # Apply changes if not in WhatIf mode
                if (-not $WhatIf) {
                    # Verify the new target exists before updating (unless Force is used)
                    if ($Force -or (Test-Path $newTargetPath)) {
                        $link.TargetPath = $newTargetPath
                        $link.WorkingDirectory = $newWorkingDir
                        $link.Save()
                        Write-Host "    ✓ Updated successfully!" -ForegroundColor Green
                        $updatedCount++
                    }
                    else {
                        Write-Host "    ⚠ WARNING: New target path doesn't exist! Use -Force to update anyway." -ForegroundColor Yellow
                        Write-Host "      Path: $newTargetPath" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "    ✓ Would be updated (WhatIf mode)" -ForegroundColor Magenta
                    $updatedCount++
                }
                
                Write-Host ""
            }
            else {
                Write-Host "Skipping: $($shortcut.Name) (not pointing to $OldPath)" -ForegroundColor Gray
            }
            
            # Release COM object
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($link) | Out-Null
        }
        catch {
            Write-Host "❌ Error processing $($shortcut.Name): $($_.Exception.Message)" -ForegroundColor Red
            Write-Host ""
        }
    }
    
    # Release COM object
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
    
    # Summary
    Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Total shortcuts processed: $totalShortcuts" -ForegroundColor White
    Write-Host "Game shortcuts found: $gameShortcuts" -ForegroundColor Yellow
    if ($WhatIf) {
        Write-Host "Shortcuts that would be updated: $updatedCount" -ForegroundColor Magenta
    }
    else {
        Write-Host "Shortcuts actually updated: $updatedCount" -ForegroundColor Green
    }
    
    if ($gameShortcuts -eq 0) {
        Write-Host ""
        Write-Host "No game shortcuts found. This could mean:" -ForegroundColor Yellow
        Write-Host "- No shortcuts point to $OldPath" -ForegroundColor Yellow
        Write-Host "- All shortcuts are already updated" -ForegroundColor Yellow
        Write-Host "- Shortcuts might be in subfolders (use -Recursive)" -ForegroundColor Yellow
    }
}
