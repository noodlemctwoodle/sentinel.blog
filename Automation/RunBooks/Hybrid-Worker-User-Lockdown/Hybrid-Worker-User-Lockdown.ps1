param(
    [Parameter(Mandatory = $true)]
    [string]$SAMAccountName
)
if (
    -not [Environment]::Is64BitProcess) { 
    Write-Error "This script must be run in a 64-bit PowerShell process." ; exit 
}
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module -Name "C:\Program Files\Microsoft Azure AD Sync\Bin\ADSync" -Verbose -ErrorAction Stop

try { 
    $User = Get-ADUser -Identity $SAMAccountName -ErrorAction Stop 
}
catch { 
    Write-Error "User $SAMAccountName not found" ; exit 
}
Write-Output "Disabling user $SAMAccountName"
try { 
    Set-ADUser -Identity $SAMAccountName -Enabled $false -ErrorAction Stop ; Write-Output "User account $SAMAccountName disabled" 
}
catch { 
    Write-Error "Error disabling user account $SAMAccountName" ; throw $_ 
}

Write-Output "User account status:"

try { 
    $Status = Get-ADUser -Identity $SAMAccountName -Properties Enabled -ErrorAction Stop `
    | Select-Object Name, SamAccountName, Enabled ; `
        Write-Output $Status 
}
catch { 
    Write-Error "Error retrieving user status" ; throw $_ 
}

Write-Output "Starting sync to Entra via AD Connect"
try { 
    Start-ADSyncSyncCycle -PolicyType Delta -ErrorAction Stop ; Write-Output "Sync completed successfully" 
} catch { 
    Write-Error "Error during sync to Entra via AD Connect" ; throw $_ 
}