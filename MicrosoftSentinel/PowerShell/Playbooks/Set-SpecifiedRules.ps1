# Define the path to search this should be the root directory where all local clients repos are stored
$path = "$PSScriptRoot\SourcePath"

# Define the logs path to write to, this should be in the root of the repository so that it is captured by .gitignore.
$logFilePath = "$PSScriptRoot\Logs\DeletedRules.txt"

# Define the Analytical Rule GUIDs to delete.
$guids = @(
    "a89bd145-073a-4362-b8c2-f8d19e9af75c",
    "a89bd145-073a-4362-b8c2-f8d19e9af75c",
    "a89bd145-073a-4362-b8c2-f8d19e9af75c"
)

function ProcessAnalyticalRules {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$Guids,

        [Parameter(Mandatory = $true)]
        [string]$LogFilePath
    )

    # Create a regular expression pattern for matching the GUIDs.
    $guidPattern = ($Guids -join "|").Replace("-", "\-")
    $pattern = "id:\s*($guidPattern)"

    # Get all .yaml files in the directory.
    $files = Get-ChildItem -Path $Path -Recurse -Filter "*.yaml"

    # Check if log file exists, if not, create it.
    if (-not (Test-Path $LogFilePath)) {
        New-Item -ItemType File -Path $LogFilePath
    }

    foreach ($file in $Files) {
        # Read the content of the file.
        $content = Get-Content $file.FullName

        # Check if the file contains any of the specified GUIDs.
        if ($content -match $pattern) {
            # Write the file path to the log file before deleting.
            Add-Content -Path $LogFilePath -Value "Deleted file: $($file.FullName) on $(Get-Date)"

            # Delete the file
            Remove-Item $file.FullName -Force
        }
    }

    # Write the completion message to the log file.
    Add-Content -Path $LogFilePath -Value "Search, delete, and logging operation completed on $(Get-Date)"
}

# Execute the function and process the rules to be deleted.
ProcessAnalyticalRules -Path $path -Guids $guids -LogFilePath $logFilePath